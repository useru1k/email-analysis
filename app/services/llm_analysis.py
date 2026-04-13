"""
LLM-powered email analysis report generation using Hugging Face.
Generates comprehensive AI-driven security assessments for email analysis results.
"""

from __future__ import annotations

import logging
from typing import Dict, Any, Optional
from huggingface_hub import InferenceClient

logger = logging.getLogger("app.llm")


class LLMAnalysisEngine:
    """
    Manages LLM-based analysis for email security reports.
    Uses Hugging Face's Llama model for intelligent threat assessment.
    """

    def __init__(self, hf_token: str):
        """
        Initialize the LLM engine with Hugging Face credentials.
        
        Args:
            hf_token: Hugging Face API token (from HF_TOKEN env var)
        """
        self.client = InferenceClient(
            model="meta-llama/Llama-3.3-70B-Instruct",
            token=hf_token,
        )
        self.system_prompt = """You are a senior cybersecurity analyst specializing in email threat analysis. 
Your role is to provide professional, detailed security assessments based on email analysis data.
Generate clear, actionable reports that explain findings in a structured manner.
Be concise but comprehensive. Use technical language appropriate for security professionals.
Start with an executive summary, then break down findings by category."""

    async def generate_ai_report(self, analysis_data: Dict[str, Any]) -> Optional[str]:
        """
        Generate an AI-powered security report using the analyzed email data.
        
        Args:
            analysis_data: Dictionary containing all analysis results with keys:
                - headers: Email header information
                - threat_score: Computed threat score (0-100)
                - auth: Authentication results (SPF, DKIM, DMARC)
                - header_issues: List of detected header issues
                - blacklist_hits: List of IPs on blacklists
                - attachments: List of file attachments with VT results
                - links: Extracted and expanded URLs
                - vt_results: VirusTotal detection results
                - ip_geos: IP geolocation data
                - mode: Analysis mode (online/offline)
        
        Returns:
            AI-generated security report as string, or None on failure
        """
        try:
            # Build comprehensive prompt for LLM
            prompt = self._build_analysis_prompt(analysis_data)
            
            logger.info("Generating AI report via Hugging Face LLM")
            
            # Call LLM with conversation history pattern
            messages = [
                {"role": "system", "content": self.system_prompt},
                {"role": "user", "content": prompt},
            ]
            
            response = self.client.chat_completion(
                messages=messages,
                max_tokens=2048,
                temperature=0.3,  # Lower temperature for consistent, factual analysis
            )
            
            report = response.choices[0].message.content
            logger.info("AI report generated successfully")
            return report
            
        except Exception as exc:
            logger.error("Failed to generate AI report: %s", exc)
            return None

    @staticmethod
    def _build_analysis_prompt(data: Dict[str, Any]) -> str:
        """
        Construct a detailed prompt with all analysis findings for the LLM.
        
        Args:
            data: Analysis results dictionary
        
        Returns:
            Formatted prompt string
        """
        headers = data.get("headers", {})
        threat_score = data.get("threat_score", 0)
        auth = data.get("auth", {})
        header_issues = data.get("header_issues", [])
        blacklist_hits = data.get("blacklist_hits", [])
        attachments = data.get("attachments", [])
        links = data.get("links", [])
        vt_results = data.get("vt_results", [])
        ip_geos = data.get("ip_geos", [])
        mode = data.get("mode", "offline")
        breakdown = data.get("breakdown", {})

        # Count detections
        attachment_count = len(attachments)
        link_count = len(links)
        malicious_attachments = sum(
            1 for att in attachments
            if att.get("vt") and att["vt"].get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0) > 0
        )
        
        vt_malicious_links = sum(
            1 for vt in vt_results
            if vt.get("vt") and vt["vt"].get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0) > 0
        )

        # Build the prompt sections
        prompt_parts = [
            "EMAIL SECURITY ANALYSIS REPORT",
            "=" * 50,
            "",
            "BASIC EMAIL INFORMATION:",
            f"From: {headers.get('From', 'Unknown')}",
            f"To: {headers.get('To', 'Unknown')}",
            f"Subject: {headers.get('Subject', 'N/A')}",
            f"Date: {headers.get('Date', 'N/A')}",
            "",
            "THREAT ASSESSMENT:",
            f"Overall Threat Score: {threat_score}/100",
            f"Risk Level: {'SAFE' if threat_score <= 30 else 'SUSPICIOUS' if threat_score <= 60 else 'MALICIOUS'}",
            f"Analysis Mode: {mode.upper()}",
            "",
            "THREAT SCORE BREAKDOWN:",
        ]
        
        # Add breakdown details
        for category, score in breakdown.items():
            prompt_parts.append(f"  • {category}: {score}")
        
        prompt_parts.extend([
            "",
            "EMAIL AUTHENTICATION:",
            f"SPF Result: {auth.get('spf', 'N/A').upper()}",
            f"DKIM Result: {auth.get('dkim', 'N/A').upper()}",
            f"DMARC Result: {auth.get('dmarc', 'N/A').upper()}",
        ])
        
        if header_issues:
            prompt_parts.extend([
                "",
                "DETECTED HEADER ISSUES:",
            ])
            for issue in header_issues:
                prompt_parts.append(f"  • {issue}")
        
        if ip_geos:
            prompt_parts.extend([
                "",
                "IP HOPS & GEOLOCATION:",
            ])
            for idx, hop in enumerate(ip_geos[:5]):  # Limit to first 5
                geo = hop.get("geo", {})
                location = f"{geo.get('city', 'Unknown')}, {geo.get('country', 'Unknown')}" if geo.get("status") == "success" else "Lookup failed"
                prompt_parts.append(f"  • Hop {idx + 1}: {hop.get('ip')} - {location}")
        
        if blacklist_hits:
            prompt_parts.extend([
                "",
                "BLACKLIST DETECTIONS:",
            ])
            for hit in blacklist_hits[:5]:  # Limit to first 5
                prompt_parts.append(f"  • {hit}")
        
        if attachment_count > 0:
            prompt_parts.extend([
                "",
                "ATTACHMENTS ANALYSIS:",
                f"Total Attachments: {attachment_count}",
                f"Malicious Detected (VirusTotal): {malicious_attachments}",
            ])
            for att in attachments[:3]:  # Show first 3 attachments
                prompt_parts.append(f"  • {att.get('filename', 'Unknown')} (SHA256: {att.get('sha256', 'N/A')[:16]}...)")
        
        if link_count > 0:
            prompt_parts.extend([
                "",
                "URL ANALYSIS:",
                f"Total URLs Found: {link_count}",
                f"Malicious Links (VirusTotal): {vt_malicious_links}",
            ])
            for link in links[:5]:  # Show first 5 links
                is_shortened = "Yes" if link.get("shortened") else "No"
                prompt_parts.append(f"  • {link.get('final', link.get('original'))} (Shortened: {is_shortened})")
        
        prompt_parts.extend([
            "",
            "ANALYSIS REQUEST:",
            "Provide a BRIEF professional security assessment in 2-3 short paragraphs ONLY:",
            "",
            "1. Executive Summary (1 paragraph): State the overall risk level and key threats detected.",
            "2. Key Findings (1 paragraph): List the most critical issues (authentication failures, malicious content, etc.).",
            "3. Recommendations (1 paragraph): Provide 2-3 specific actionable security recommendations.",
            "",
            "Be concise. Avoid excessive detail. Focus on what matters most for security decisions.",
        ])
        
        return "\n".join(prompt_parts)


async def generate_analysis_report(analysis_data: Dict[str, Any], hf_token: Optional[str]) -> Optional[str]:
    """
    Convenience function to generate an AI report.
    
    Args:
        analysis_data: Email analysis results
        hf_token: Hugging Face API token
    
    Returns:
        Generated report or None if token not available or generation fails
    """
    if not hf_token:
        logger.warning("HF_TOKEN not configured, skipping AI report generation")
        return None
    
    engine = LLMAnalysisEngine(hf_token)
    return await engine.generate_ai_report(analysis_data)
