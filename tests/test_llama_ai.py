#!/usr/bin/env python
"""Test the AI analysis implementation with Hugging Face Llama model."""

import asyncio
import os
from dotenv import load_dotenv

# Load environment
load_dotenv()

from app.services.ai_analysis import (
    get_inference_client,
    generate_ai_threat_report,
    generate_rule_based_report
)

async def main():
    print("="*80)
    print(" EMAIL THREAT ANALYSIS - AI SYSTEM TEST")
    print("="*80)
    
    # Check environment
    hf_token = os.getenv("HF_TOKEN")
    print(f"\n📋 Configuration Check:")
    print(f"   HF_TOKEN Present: {'✓ Yes' if hf_token else '✗ No (will use rule-based fallback)'}")
    
    # Test case: High-threat phishing email
    test_email = {
        'content': 'Click here immediately to verify your account or it will be suspended. Your security is at critical risk!',
        'headers': {
            'Subject': 'URGENT SECURITY ALERT: Verify Your Account Now',
            'From': 'security-alerts@bank-verify-account.com',
            'To': 'user@gmail.com'
        },
        'threat_score': 88,
        'analysis': {
            'spf': 'fail',
            'dkim': 'fail',
            'dmarc': 'fail',
            'auth': 'fail',
            'risky_links': 3,
            'risky_attachments': ['invoice.exe', 'document.zip'],
            'vt_attachments': ['invoice.exe'],
            'blacklist_hits': 2,
            'score_breakdown': {
                'auth': 30,
                'blacklists': 30,
                'attachments': 25,
                'links': 3
            }
        }
    }
    
    print("\n" + "="*80)
    print(" TEST EMAIL DETAILS")
    print("="*80)
    print(f"Subject:       {test_email['headers']['Subject']}")
    print(f"From:          {test_email['headers']['From']}")
    print(f"To:            {test_email['headers']['To']}")
    print(f"Threat Score:  {test_email['threat_score']}/100 (CRITICAL)")
    
    print("\n" + "="*80)
    print(" GENERATING AI THREAT REPORT")
    print("="*80)
    print("Processing with Hugging Face Llama-3.3-70B model...")
    print("(or rule-based fallback if HF_TOKEN not available)\n")
    
    try:
        report = await generate_ai_threat_report(
            test_email['content'],
            test_email['headers'],
            test_email['threat_score'],
            test_email['analysis']
        )
        
        print("┌" + "─"*78 + "┐")
        print("│ " + " "*76 + " │")
        print("│ AI THREAT ANALYSIS REPORT" + " "*50 + " │")
        print("│ " + " "*76 + " │")
        print("└" + "─"*78 + "┘")
        print("\n" + report.get('ai_report', 'No report generated') + "\n")
        
        print("="*80)
        print(" ✓ TEST COMPLETED SUCCESSFULLY")
        print("="*80)
        
    except Exception as e:
        print(f"\n✗ ERROR: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())
