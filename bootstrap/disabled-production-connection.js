function receipt(reasonCode) {
  return Object.freeze({
    schemaVersion: "scoperange-disabled-production-connection-receipt-v1",
    disposition: "rejected",
    reasonCode,
    secretReads: 0,
    networkAttempts: 0,
    providerConnections: 0,
    databaseConnections: 0,
    pricingEffects: 0,
    productionAuthority: "none"
  });
}

export function evaluateDisabledProductionConnection(input) {
  if (input === undefined) return receipt("connection_not_configured");
  return receipt("connection_input_rejected");
}
