#!/bin/bash
# Deploys the Daon TrustX connector into a WSO2 Identity Server distribution.
# Extract this archive inside <IS_HOME>, change into the extracted directory and run this script.

mkdir -p ../repository/resources/identity/extensions/identity-providers/
mv ./dropins/* ../repository/components/dropins/
mv ./identity-providers/* ../repository/resources/identity/extensions/identity-providers/
