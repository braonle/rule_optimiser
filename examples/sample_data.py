"""
    Sample policy exports used by the examples.

    Every dictionary below has the shape of the corresponding API response and is
    passed to the optimisers without modification, exactly as a real export would be:

    * FIREWALL_RULES   – ZIA Firewall Control
                         https://help.zscaler.com/zia/firewall-policies#/firewallFilteringRules-get
    * URL_RULES        – ZIA URL Filtering
                         https://help.zscaler.com/zia/url-filtering-policies#/urlFilteringRules-get
    * ACCESS_RULES     – ZPA Access Policy
                         https://help.zscaler.com/zpa/configuring-access-policies-using-api

    The data is deliberately small and hand-crafted so that the clusters the
    optimiser reports can be verified by eye.
"""

# Three regional DNS rules that differ in "locations" only, two anonymiser rules
# where one is a strict subset of the other, and a global NTP rule that has no
# location scope at all. The last two entries are skipped by the optimiser:
# the default rule cannot be edited and predefined rules are read-only.
FIREWALL_RULES: list[dict] = [
    {
        "id": 1,
        "name": "Allow DNS - EMEA",
        "order": 1,
        "rank": 7,
        "action": "ALLOW",
        "state": "ENABLED",
        "defaultRule": False,
        "nwServices": [{"id": 101, "name": "DNS"}],
        "locations": [{"id": 201, "name": "Paris HQ"}],
    },
    {
        "id": 2,
        "name": "Allow DNS - AMER",
        "order": 2,
        "rank": 7,
        "action": "ALLOW",
        "state": "ENABLED",
        "defaultRule": False,
        "nwServices": [{"id": 101, "name": "DNS"}],
        "locations": [{"id": 202, "name": "New York HQ"}],
    },
    {
        "id": 3,
        "name": "Allow DNS - APAC",
        "order": 3,
        "rank": 7,
        "action": "ALLOW",
        "state": "ENABLED",
        "defaultRule": False,
        "nwServices": [{"id": 101, "name": "DNS"}],
        "locations": [{"id": 203, "name": "Tokyo HQ"}],
    },
    {
        "id": 4,
        "name": "Allow NTP - Global",
        "order": 4,
        "rank": 7,
        "action": "ALLOW",
        "state": "ENABLED",
        "defaultRule": False,
        "nwServices": [{"id": 102, "name": "NTP"}],
    },
    {
        "id": 5,
        "name": "Block TOR",
        "order": 5,
        "rank": 7,
        "action": "BLOCK_DROP",
        "state": "ENABLED",
        "defaultRule": False,
        "nwApplications": ["TOR"],
    },
    {
        "id": 6,
        "name": "Block anonymisers",
        "order": 6,
        "rank": 7,
        "action": "BLOCK_DROP",
        "state": "ENABLED",
        "defaultRule": False,
        "nwApplications": ["TOR", "ULTRASURF"],
    },
    {
        "id": 7,
        "name": "Zscaler Proxy Traffic",
        "order": 7,
        "rank": 7,
        "action": "ALLOW",
        "state": "ENABLED",
        "defaultRule": False,
        "predefined": True,
    },
    {
        "id": 8,
        "name": "Default Firewall Filtering Rule",
        "order": 9,
        "rank": 7,
        "action": "ALLOW",
        "state": "ENABLED",
        "defaultRule": True,
    },
]

# Two social-media rules that differ in the department they apply to, plus a
# cautioned rule for streaming that shares the same audience as neither.
URL_RULES: list[dict] = [
    {
        "id": 11,
        "name": "Block social media - Finance",
        "order": 1,
        "rank": 7,
        "action": "BLOCK",
        "state": "ENABLED",
        "urlCategories": ["SOCIAL_NETWORKING"],
        "protocols": ["HTTPS_RULE", "HTTP_RULE"],
        "departments": [{"id": 301, "name": "Finance"}],
    },
    {
        "id": 12,
        "name": "Block social media - Legal",
        "order": 2,
        "rank": 7,
        "action": "BLOCK",
        "state": "ENABLED",
        "urlCategories": ["SOCIAL_NETWORKING"],
        "protocols": ["HTTPS_RULE", "HTTP_RULE"],
        "departments": [{"id": 302, "name": "Legal"}],
    },
    {
        "id": 13,
        "name": "Block social media - Engineering",
        "order": 3,
        "rank": 7,
        "action": "BLOCK",
        "state": "ENABLED",
        "urlCategories": ["SOCIAL_NETWORKING"],
        "protocols": ["HTTPS_RULE", "HTTP_RULE"],
        "departments": [{"id": 303, "name": "Engineering"}],
    },
    {
        "id": 14,
        "name": "Caution streaming",
        "order": 4,
        "rank": 7,
        "action": "CAUTION",
        "state": "ENABLED",
        "urlCategories": ["STREAMING_MEDIA"],
        "protocols": ["HTTPS_RULE", "HTTP_RULE"],
        "departments": [{"id": 303, "name": "Engineering"}],
    },
]

# Three ZPA rules granting the same application group to different audiences, plus a
# fourth one matching on a SCIM attribute instead of a SCIM group - that attribute
# turns into the dynamic "SCIM department" criterion on the rule object.
ACCESS_RULES: list[dict] = [
    {
        "id": "21",
        "name": "Allow HR apps - Berlin",
        "ruleOrder": "1",
        "action": "ALLOW",
        "disabled": "0",
        "operator": "AND",
        "conditions": [
            {
                "operator": "OR",
                "operands": [
                    {"objectType": "APP_GROUP", "name": "HR Applications",
                     "lhs": "id", "rhs": "401"},
                ],
            },
            {
                "operator": "OR",
                "operands": [
                    {"objectType": "SCIM_GROUP", "name": "Okta",
                     "lhs": "501", "rhs": "Berlin Staff"},
                ],
            },
        ],
    },
    {
        "id": "22",
        "name": "Allow HR apps - Munich",
        "ruleOrder": "2",
        "action": "ALLOW",
        "disabled": "0",
        "operator": "AND",
        "conditions": [
            {
                "operator": "OR",
                "operands": [
                    {"objectType": "APP_GROUP", "name": "HR Applications",
                     "lhs": "id", "rhs": "401"},
                ],
            },
            {
                "operator": "OR",
                "operands": [
                    {"objectType": "SCIM_GROUP", "name": "Okta",
                     "lhs": "502", "rhs": "Munich Staff"},
                ],
            },
        ],
    },
    {
        "id": "23",
        "name": "Allow HR apps - Browser only",
        "ruleOrder": "3",
        "action": "ALLOW",
        "disabled": "0",
        "operator": "AND",
        "conditions": [
            {
                "operator": "OR",
                "operands": [
                    {"objectType": "APP_GROUP", "name": "HR Applications",
                     "lhs": "id", "rhs": "401"},
                ],
            },
            {
                "operator": "OR",
                "operands": [
                    {"objectType": "SCIM_GROUP", "name": "Okta",
                     "lhs": "501", "rhs": "Berlin Staff"},
                ],
            },
            {
                "operator": "OR",
                "operands": [
                    {"objectType": "CLIENT_TYPE", "name": "Browser Isolation", "lhs": "id",
                     "rhs": "zpn_client_type_browser_isolation"},
                ],
            },
        ],
    },
    {
        "id": "24",
        "name": "Allow HR apps - Contractors",
        "ruleOrder": "4",
        "action": "ALLOW",
        "disabled": "0",
        "operator": "AND",
        "conditions": [
            {
                "operator": "OR",
                "operands": [
                    {"objectType": "APP_GROUP", "name": "HR Applications",
                     "lhs": "id", "rhs": "401"},
                ],
            },
            {
                "operator": "OR",
                "operands": [
                    {"objectType": "SCIM", "name": "department",
                     "lhs": "503", "rhs": "Contractors"},
                ],
            },
        ],
    },
]


# The SSL Inspection, File Type Control and Sandbox APIs are not published; the
# dictionaries below follow the shape the library reverse-engineered from the UI.
# Note the nested "action" object of an SSL rule - the sub-actions that the optimiser
# compares live under a key named after the action type.
SSL_RULES: list[dict] = [
    {
        "id": 31,
        "name": "Do not decrypt banking",
        "order": 1,
        "rank": 7,
        "state": "ENABLED",
        "defaultRule": False,
        "urlCategories": ["FINANCE"],
        "action": {
            "type": "DO_NOT_DECRYPT",
            "showEUN": False,
            "doNotDecryptSubActions": {
                "bypassOtherPolicies": False,
                "ocspCheck": True,
                "serverCertificates": "ALLOW",
                "minTLSVersion": "CLIENT_TLS_1_2",
            },
        },
    },
    {
        "id": 32,
        "name": "Do not decrypt healthcare",
        "order": 2,
        "rank": 7,
        "state": "ENABLED",
        "defaultRule": False,
        "urlCategories": ["HEALTH"],
        "action": {
            "type": "DO_NOT_DECRYPT",
            "showEUN": False,
            "doNotDecryptSubActions": {
                "bypassOtherPolicies": False,
                "ocspCheck": True,
                "serverCertificates": "ALLOW",
                "minTLSVersion": "CLIENT_TLS_1_2",
            },
        },
    },
    {
        "id": 33,
        "name": "Decrypt everything else",
        "order": 3,
        "rank": 7,
        "state": "ENABLED",
        "defaultRule": False,
        "action": {
            "type": "DECRYPT",
            "showEUN": True,
            "decryptSubActions": {
                "serverCertificates": "BLOCK",
                "ocspCheck": True,
                "blockUndecrypt": True,
                "http2Enabled": False,
                "minClientTLSVersion": "CLIENT_TLS_1_2",
                "minServerTLSVersion": "SERVER_TLS_1_2",
            },
        },
    },
]

FILETYPE_RULES: list[dict] = [
    {
        "id": 41,
        "name": "Block executables - Finance",
        "order": 1,
        "rank": 7,
        "state": "ENABLED",
        "filteringAction": "BLOCK",
        "operation": "DOWNLOAD",
        "fileTypes": ["FTCATEGORY_EXE", "FTCATEGORY_MSI"],
        "protocols": ["HTTPS_RULE", "HTTP_RULE"],
        "departments": [{"id": 301, "name": "Finance"}],
    },
    {
        "id": 42,
        "name": "Block executables - Legal",
        "order": 2,
        "rank": 7,
        "state": "ENABLED",
        "filteringAction": "BLOCK",
        "operation": "DOWNLOAD",
        "fileTypes": ["FTCATEGORY_EXE", "FTCATEGORY_MSI"],
        "protocols": ["HTTPS_RULE", "HTTP_RULE"],
        "departments": [{"id": 302, "name": "Legal"}],
    },
    {
        "id": 43,
        "name": "Block archives - Finance",
        "order": 3,
        "rank": 7,
        "state": "ENABLED",
        "filteringAction": "BLOCK",
        "operation": "DOWNLOAD",
        "fileTypes": ["FTCATEGORY_ZIP", "FTCATEGORY_RAR"],
        "protocols": ["HTTPS_RULE", "HTTP_RULE"],
        "departments": [{"id": 301, "name": "Finance"}],
    },
]

SANDBOX_RULES: list[dict] = [
    {
        "id": 51,
        "name": "Quarantine executables",
        "order": 1,
        "rank": 7,
        "state": "ENABLED",
        "firstTimeOperation": "QUARANTINE",
        "baRuleAction": "BLOCK",
        "mlActionEnabled": True,
        "fileTypes": ["FTCATEGORY_EXE"],
        "protocols": ["HTTPS_RULE", "HTTP_RULE"],
        "baPolicyCategories": ["ADWARE_BLOCK", "MALWARE_BLOCK"],
    },
    {
        "id": 52,
        "name": "Quarantine documents",
        "order": 2,
        "rank": 7,
        "state": "ENABLED",
        "firstTimeOperation": "QUARANTINE",
        "baRuleAction": "BLOCK",
        "mlActionEnabled": True,
        "fileTypes": ["FTCATEGORY_MS_WORD", "FTCATEGORY_MS_EXCEL"],
        "protocols": ["HTTPS_RULE", "HTTP_RULE"],
        "baPolicyCategories": ["ADWARE_BLOCK", "MALWARE_BLOCK"],
    },
    {
        "id": 53,
        "name": "Allow trusted archives",
        "order": 3,
        "rank": 7,
        "state": "ENABLED",
        "firstTimeOperation": "ALLOW_SCAN",
        "baRuleAction": "ALLOW",
        "mlActionEnabled": False,
        "fileTypes": ["FTCATEGORY_ZIP"],
        "protocols": ["HTTPS_RULE", "HTTP_RULE"],
        "baPolicyCategories": ["MALWARE_BLOCK"],
    },
]
