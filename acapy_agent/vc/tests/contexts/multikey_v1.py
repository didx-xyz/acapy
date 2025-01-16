MULTIKEY_V1 = {
    "@context": {
        "id": "@id",
        "type": "@type",
        "@protected": True,
        "Multikey": {
            "@id": "https://w3id.org/security#Multikey",
            "@context": {
                "@protected": True,
                "id": "@id",
                "type": "@type",
                "controller": {
                    "@id": "https://w3id.org/security#controller",
                    "@type": "@id",
                },
                "revoked": {
                    "@id": "https://w3id.org/security#revoked",
                    "@type": "http://www.w3.org/2001/XMLSchema#dateTime",
                },
                "expires": {
                    "@id": "https://w3id.org/security#expiration",
                    "@type": "http://www.w3.org/2001/XMLSchema#dateTime",
                },
                "publicKeyMultibase": {
                    "@id": "https://w3id.org/security#publicKeyMultibase",
                    "@type": "https://w3id.org/security#multibase",
                },
                "secretKeyMultibase": {
                    "@id": "https://w3id.org/security#secretKeyMultibase",
                    "@type": "https://w3id.org/security#multibase",
                },
            },
        },
    }
}
