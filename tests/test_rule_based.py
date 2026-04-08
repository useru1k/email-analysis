from app.services.ai_analysis import generate_rule_based_report

report = generate_rule_based_report(
    'Please click here to verify your credentials urgently',
    {
        'Subject': 'URGENT: Verify Your Account Now',
        'From': 'security@fake-bank-phishing.com'
    },
    75,
    {
        'spf': 'fail',
        'dkim': 'fail', 
        'risky_links': 2,
        'blacklist_hits': 1,
        'vt_attachments': ['malware.exe']
    }
)

print(report)
