import json

NAME = "github.com/kelbyludwig/adblocker"
VERSION = "1"
BLOCK_LIST = [
    "collect.igodigital.com",
    "taboola.com",
    "amazon-adsystem.com",
    "googlesyndication.com",
    "adsafeprotected.com",
    "doubleclick.net",
    "moatads.com",
    "id5-sync.com",
    "sofia.trustx.org",
    "emxdgt.com",
    "go.sonobi.com",
    "contextweb.com",
    "bidswitch.net",
    "mathtag.com",
    "rfihub.com",
    "adsrvr.org",
    "googleadservices.com"
    "google-analytics.com"
]


def manifest():
    return {
        "name": NAME,
        "version": VERSION,
        "declarative_net_request": {
            "rule_resources": [
                {"id": "ruleset_1", "enabled": True, "path": "rules.json"}
            ]
        },
        "permissions": ["declarativeNetRequest"],
        "manifest_version": 3,
    }


def _rule(i, domain):
    return {
        "id": i,
        "priority": 1,
        "action": {"type": "block"},
        "condition": {
            "urlFilter": domain,
            "resourceTypes": [
                "main_frame",
                "sub_frame",
                "stylesheet",
                "script",
                "image",
                "font",
                "object",
                "xmlhttprequest",
                "ping",
                "csp_report",
                "media",
                "websocket",
                "other",
            ],
        },
    }


def rules():
    return [_rule(i+1, domain) for i, domain in enumerate(BLOCK_LIST)]


if __name__ == "__main__":
    with open("manifest.json", "w") as f:
        json.dump(manifest(), f, sort_keys=True, indent=2)

    with open("rules.json", "w") as f:
        json.dump(rules(), f, sort_keys=True, indent=2)
