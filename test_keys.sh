#!/bin/bash
# Test script to verify public key extraction

echo "Generating test keys..."
KEYS=$(cargo run --release -- gen-keys 2>/dev/null)

PRIV_KEY=$(echo "$KEYS" | grep "Private Key:" | cut -d' ' -f3)
PUB_KEY=$(echo "$KEYS" | grep "Public Key:" | cut -d' ' -f3)

echo "Private Key: $PRIV_KEY"
echo "Public Key from gen-keys: $PUB_KEY"

# Now we need to extract the public key from a certificate generated from this private key
# and compare it to the gen-keys output

echo ""
echo "This public key should match what's in the peer config"
echo "and what the certificate verifier extracts from the SPKI"
