#!/usr/bin/env node

/**
 * Test script for ACA status checking logic
 * Run with: node test/aca.test.js
 */

// Simplified versions of the helper functions for testing
function parseEntitlements(headerValue) {
  if (!headerValue) return [];
  if (Array.isArray(headerValue)) return headerValue;
  if (typeof headerValue === 'string') {
    return headerValue
      .split(';')
      .map(entitlement => entitlement.trim())
      .filter(entitlement => entitlement.length > 0);
  }
  return [];
}

function parseAffiliations(headerValue) {
  if (!headerValue) return [];
  if (Array.isArray(headerValue)) return headerValue;
  if (typeof headerValue === 'string') {
    return headerValue
      .split(';')
      .map(aff => aff.trim())
      .filter(aff => aff.length > 0);
  }
  return [];
}

function checkAcademicStatus(affiliations, scopedAffiliations, entitlements) {
  const unscopedAffs = parseAffiliations(affiliations);
  const scopedAffs = parseAffiliations(scopedAffiliations);
  const ents = parseEntitlements(entitlements);

  const academicAffiliations = ['member', 'student', 'faculty', 'employee'];

  // 1. Check unscoped affiliations
  for (const aff of unscopedAffs) {
    if (academicAffiliations.includes(aff.toLowerCase())) {
      return true;
    }
  }

  // 2. Check CLARIN special case
  const hasClarinMember = scopedAffs.some(aff =>
    aff.toLowerCase() === 'member@clarin.eu'
  );
  const hasClarinAcademicEntitlement = ents.some(ent =>
    ent === 'http://www.clarin.eu/entitlement/academic'
  );
  if (hasClarinMember && hasClarinAcademicEntitlement) {
    return true;
  }

  // 3. Check other scoped affiliations (excluding CLARIN member@clarin.eu)
  for (const aff of scopedAffs) {
    const lowerAff = aff.toLowerCase();
    if (lowerAff === 'member@clarin.eu') {
      continue;
    }
    for (const academicRole of academicAffiliations) {
      if (lowerAff.startsWith(academicRole + '@')) {
        return true;
      }
    }
  }

  // 4. Check LBR ACA entitlement
  const hasLbrAca = ents.some(ent =>
    ent === 'urn:nbn:fi:lb-2016110710@LBR'
  );
  if (hasLbrAca) {
    return true;
  }

  return false;
}

// Test cases
const tests = [
  {
    name: "Unscoped affiliation: member",
    aff: "member",
    scopedAff: null,
    ent: null,
    expected: true
  },
  {
    name: "Unscoped affiliation: student",
    aff: "student",
    scopedAff: null,
    ent: null,
    expected: true
  },
  {
    name: "Unscoped affiliation: faculty",
    aff: "faculty",
    scopedAff: null,
    ent: null,
    expected: true
  },
  {
    name: "Unscoped affiliation: employee",
    aff: "employee",
    scopedAff: null,
    ent: null,
    expected: true
  },
  {
    name: "Unscoped affiliation: affiliate (should not grant ACA)",
    aff: "affiliate",
    scopedAff: null,
    ent: null,
    expected: false
  },
  {
    name: "Unscoped affiliation: library-walk-in (should not grant ACA)",
    aff: "library-walk-in",
    scopedAff: null,
    ent: null,
    expected: false
  },
  {
    name: "CLARIN special case: member@clarin.eu with academic entitlement",
    aff: null,
    scopedAff: "member@clarin.eu",
    ent: "http://www.clarin.eu/entitlement/academic",
    expected: true
  },
  {
    name: "CLARIN special case: member@clarin.eu WITHOUT academic entitlement (should not grant ACA)",
    aff: null,
    scopedAff: "member@clarin.eu",
    ent: null,
    expected: false
  },
  {
    name: "Scoped affiliation: member@helsinki.fi",
    aff: null,
    scopedAff: "member@helsinki.fi",
    ent: null,
    expected: true
  },
  {
    name: "Scoped affiliation: student@jyu.fi",
    aff: null,
    scopedAff: "student@jyu.fi",
    ent: null,
    expected: true
  },
  {
    name: "Scoped affiliation: faculty@utu.fi",
    aff: null,
    scopedAff: "faculty@utu.fi",
    ent: null,
    expected: true
  },
  {
    name: "Scoped affiliation: employee@aalto.fi",
    aff: null,
    scopedAff: "employee@aalto.fi",
    ent: null,
    expected: true
  },
  {
    name: "LBR ACA entitlement",
    aff: null,
    scopedAff: null,
    ent: "urn:nbn:fi:lb-2016110710@LBR",
    expected: true
  },
  {
    name: "No academic credentials",
    aff: null,
    scopedAff: null,
    ent: null,
    expected: false
  },
  {
    name: "Multiple entitlements including LBR ACA",
    aff: null,
    scopedAff: null,
    ent: "urn:nbn:fi:lb-2022031701@LBR;urn:nbn:fi:lb-2016110710@LBR",
    expected: true
  },
  {
    name: "Multiple affiliations including member",
    aff: "member;employee",
    scopedAff: null,
    ent: null,
    expected: true
  }
];

console.log('Testing ACA Status Checking Logic');
console.log('='.repeat(70));

let passed = 0;
let failed = 0;

tests.forEach(test => {
  const result = checkAcademicStatus(test.aff, test.scopedAff, test.ent);
  const status = result === test.expected ? '✓ PASS' : '✗ FAIL';

  if (result === test.expected) {
    passed++;
  } else {
    failed++;
  }

  console.log(`${status} - ${test.name}`);
  if (result !== test.expected) {
    console.log(`  Expected: ${test.expected}, Got: ${result}`);
  }
});

console.log('='.repeat(70));
console.log(`Results: ${passed} passed, ${failed} failed`);

process.exit(failed > 0 ? 1 : 0);
