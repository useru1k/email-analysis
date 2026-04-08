import asyncio
from app.services.ai_analysis import generate_ai_threat_report

async def test():
    result = await generate_ai_threat_report(
        'Click here to verify your account now',
        {'Subject': 'Urgent Action Required', 'From': 'spam@suspicious.com'},
        75,
        {'spf': 'fail', 'dkim': 'fail', 'risky_links': 2}
    )
    print("✓ Report generated successfully!")
    print("\n" + "="*60)
    print(result)
    print("="*60)

if __name__ == "__main__":
    asyncio.run(test())
