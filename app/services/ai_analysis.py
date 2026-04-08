"""
AI Analysis Service for Email Threat Detection

This module provides AI-powered analysis of email content using Hugging Face models
to identify potential threats, phishing attempts, and suspicious patterns.
"""

import os
import logging
from typing import Dict, Any, Optional
from dotenv import load_dotenv

try:
    from huggingface_hub import InferenceClient
    HF_AVAILABLE = True
except ImportError:
    HF_AVAILABLE = False

logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

def get_inference_client() -> Optional[InferenceClient]:
    """Get Hugging Face InferenceClient if available and configured."""
    if not HF_AVAILABLE:
        logger.warning("Hugging Face hub not available")
        return None

    hf_token = os.getenv("HF_TOKEN")
    if not hf_token:
        logger.warning("HF_TOKEN not found in environment")
        return None

    try:
        client = InferenceClient(
            model="meta-llama/Llama-3.3-70B-Instruct",
            token=hf_token,
        )
        return client
    except Exception as e:
        logger.error(f"Failed to create InferenceClient: {e}")
        return None

async def generate_ai_threat_report(
    email_body: str,
    headers: Dict[str, Any],
    threat_score: int,
    analysis_breakdown: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Generate an AI-powered threat analysis report for an email.

    Args:
        email_body: The text content of the email
        headers: Email headers dictionary
        threat_score: Calculated threat score (0-100)
        analysis_breakdown: Detailed analysis results

    Returns:
        Dictionary containing the AI report and metadata
    """
    client = get_inference_client()

    if not client:
        # Fallback to rule-based analysis
        return await generate_rule_based_report(email_body, headers, threat_score, analysis_breakdown)

    try:
        # Create the analysis prompt
        system_prompt = """You are an expert cybersecurity analyst specializing in email threat detection.
Your task is to analyze email content for potential security threats including phishing, malware, spam, and social engineering attacks.

Analyze the provided email data and provide a comprehensive threat assessment that includes:

1. **THREAT LEVEL ASSESSMENT**: High/Medium/Low risk with justification
2. **ATTACK VECTOR ANALYSIS**: What type of attack this appears to be (phishing, malware, spam, etc.)
3. **SUSPICIOUS INDICATORS**: Specific elements that raise concern
4. **RECOMMENDED ACTIONS**: What the recipient should do
5. **TECHNICAL DETAILS**: Any technical observations about headers, content, or patterns

Be specific, evidence-based, and focus on actionable intelligence. Keep the analysis concise but comprehensive."""

        # Format the email data for analysis
        email_content = f"""
EMAIL ANALYSIS REQUEST:

HEADERS:
{chr(10).join(f"{k}: {v}" for k, v in headers.items())}

EMAIL BODY:
{email_body}

THREAT SCORE: {threat_score}/100

ANALYSIS BREAKDOWN:
{chr(10).join(f"- {k}: {v}" for k, v in analysis_breakdown.items())}

Please provide your expert threat analysis below:
"""

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": email_content}
        ]

        # Get AI analysis
        response = client.chat_completion(
            messages=messages,
            max_tokens=1024,  # Increased for comprehensive analysis
            temperature=0.3,  # Lower temperature for more consistent analysis
        )

        ai_report = response.choices[0].message.content

        return {
            "ai_report": ai_report,
            "model": "meta-llama/Llama-3.3-70B-Instruct",
            "model_description": "Meta Llama 3.3 70B Instruct via Hugging Face",
            "method": "Hugging Face Inference API",
            "conversation_turns": 1,
            "prompt_used": system_prompt[:200] + "..."  # Truncated for brevity
        }

    except Exception as e:
        logger.error(f"AI analysis failed: {e}")
        # Fallback to rule-based
        return await generate_rule_based_report(email_body, headers, threat_score, analysis_breakdown)

async def generate_rule_based_report(
    email_body: str,
    headers: Dict[str, Any],
    threat_score: int,
    analysis_breakdown: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Generate a rule-based threat analysis report as fallback when AI is unavailable.

    Args:
        email_body: The text content of the email
        headers: Email headers dictionary
        threat_score: Calculated threat score (0-100)
        analysis_breakdown: Detailed analysis results

    Returns:
        Dictionary containing the rule-based report and metadata
    """
    # Determine threat level
    if threat_score >= 70:
        threat_level = "HIGH"
        description = "This email shows multiple indicators of being a sophisticated threat."
    elif threat_score >= 40:
        threat_level = "MEDIUM"
        description = "This email has some suspicious characteristics that warrant caution."
    else:
        threat_level = "LOW"
        description = "This email appears relatively safe but should still be verified."

    # Build rule-based analysis
    analysis_points = []

    # Check for common phishing indicators
    suspicious_words = ["urgent", "verify", "account", "suspended", "security", "alert", "click here"]
    body_lower = email_body.lower()
    found_suspicious = [word for word in suspicious_words if word in body_lower]

    if found_suspicious:
        analysis_points.append(f"Found suspicious keywords: {', '.join(found_suspicious)}")

    # Check authentication
    auth_status = analysis_breakdown.get("auth", "unknown")
    if auth_status == "fail":
        analysis_points.append("Email authentication failed (SPF/DKIM/DMARC)")

    # Check attachments
    risky_attachments = analysis_breakdown.get("risky_attachments", [])
    if risky_attachments:
        analysis_points.append(f"Risky attachments detected: {', '.join(risky_attachments)}")

    # Check links
    risky_links = analysis_breakdown.get("risky_links", 0)
    if risky_links > 0:
        analysis_points.append(f"Found {risky_links} potentially risky links")

    # Check blacklists
    blacklist_hits = analysis_breakdown.get("blacklist_hits", 0)
    if blacklist_hits > 0:
        analysis_points.append(f"IP addresses associated with {blacklist_hits} blacklist entries")

    # Generate recommendations
    recommendations = []
    if threat_score >= 70:
        recommendations.extend([
            "DO NOT click any links or open attachments",
            "Delete this email immediately",
            "Report to your IT security team",
            "Verify any account issues directly through official channels"
        ])
    elif threat_score >= 40:
        recommendations.extend([
            "Verify the sender through official channels",
            "Do not click links - navigate manually to known sites",
            "Scan attachments with antivirus before opening",
            "Be cautious with any personal information requests"
        ])
    else:
        recommendations.append("Exercise normal caution when interacting with this email")

    # Build the report
    report = f"""EMAIL THREAT ANALYSIS REPORT

THREAT LEVEL: {threat_level} ({threat_score}/100)
{description}

ANALYSIS SUMMARY:
{chr(10).join(f"• {point}" for point in analysis_points) if analysis_points else "• No major red flags detected"}

RECOMMENDED ACTIONS:
{chr(10).join(f"• {rec}" for rec in recommendations)}

This analysis is based on automated rule-based detection. For high-threat emails, consider manual review by security experts."""

    return {
        "ai_report": report,
        "model": "Rule-based Analysis",
        "model_description": "Automated pattern matching and heuristic analysis",
        "method": "Rule-based Fallback",
        "conversation_turns": 1,
        "prompt_used": "Automated rule-based analysis"
    }