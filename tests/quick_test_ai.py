#!/usr/bin/env python
"""
QUICK REFERENCE - Multi-Turn AI Threat Analysis

Run this script to demonstrate the new AI capabilities.
"""

import asyncio
from app.services.ai_analysis import generate_ai_threat_report

# Example: High-threat phishing email
HIGH_THREAT_EMAIL = {
    'content': 'Click here to verify account or face suspension',
    'headers': {
        'Subject': 'URGENT: Verify Your Account',
        'From': 'security@fake-bank.com'
    },
    'threat_score': 85,
    'analysis': {
        'spf': 'fail',
        'dkim': 'fail',
        'risky_links': 2
    }
}

async def test_ai():
    """Test the multi-turn AI analysis."""
    result = await generate_ai_threat_report(
        HIGH_THREAT_EMAIL['content'],
        HIGH_THREAT_EMAIL['headers'],
        HIGH_THREAT_EMAIL['threat_score'],
        HIGH_THREAT_EMAIL['analysis']
    )
    
    print("🤖 AI MODEL:", result.get('model'))
    print("📝 METHOD:", result.get('method'))
    print("🔄 TURNS:", result.get('conversation_turns'))
    print("\n" + "="*70)
    print(result.get('ai_report'))
    print("="*70)

if __name__ == "__main__":
    asyncio.run(test_ai())
