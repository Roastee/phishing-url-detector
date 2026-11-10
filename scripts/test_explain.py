from src.phishdetect.explain import explain_url
r = explain_url('https://www.google.com')
print('Reasons:', len(r['reasons']))
for reas in r['reasons'][:3]:
    print(f'  {reas["feature"]}: {reas["explanation"]}')