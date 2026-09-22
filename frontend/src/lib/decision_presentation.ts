import type { AuthorizationEffect } from "./api_types";

export interface DecisionPresentation {
  label: "ALLOW" | "DENY";
  ariaLabel: "Authorization allowed" | "Authorization denied";
  className: string;
}

/** Shared semantic styling for authorization outcomes across console views. */
export function decisionPresentation(effect: AuthorizationEffect): DecisionPresentation {
  if (effect === "allow") {
    return {
      label: "ALLOW",
      ariaLabel: "Authorization allowed",
      className: "border-allow text-allow",
    };
  }
  return {
    label: "DENY",
    ariaLabel: "Authorization denied",
    className: "border-deny text-deny",
  };
}
