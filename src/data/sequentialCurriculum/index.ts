import { SecurityInvariant } from "../../types/invariants";
import { tier1FoundationsRules } from "./tier1Foundations";
import { tier2PractitionerRules } from "./tier2Practitioner";
import { tier3AdvancedRules } from "./tier3Advanced";
import { tier4StaffFrontierRules } from "./tier4StaffFrontier";

export { tier1FoundationsRules, tier2PractitionerRules, tier3AdvancedRules, tier4StaffFrontierRules };

export const allSequentialRules: SecurityInvariant[] = [
  ...tier1FoundationsRules,
  ...tier2PractitionerRules,
  ...tier3AdvancedRules,
  ...tier4StaffFrontierRules
];
