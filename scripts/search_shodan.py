#!/usr/bin/python3

import shodan

# simple script to query Shodan
api_key = "API"
api = shodan.Shodan(api_key)

try:
    # nothong fancy here
    results = api.search("cups port:631")
    print(f"Results: {results['total']}")

    # Get the results
    for result in results['matches']:
        print(f"IP : {result['ip_str']}")
        print(f"Port : {result['port']}")
        print(f"Organisation : {result.get('org', 'N/A')}")
        print(f"Pays : {result['location']['country_name']}")
        print("=" * 50)
except shodan.APIError as e:
    print(f"Erreur API : {e}")
