/**
 * CivicShield — Demo Cases
 * 5 clearly labelled synthetic test cases.
 * These are fabricated examples for demonstration purposes only.
 * None of these represent real government communications.
 */

import type { DemoCase } from "../types/analysis";

export const DEMO_CASES: DemoCase[] = [
  {
    id: "demo-genuine",
    label: "Demo A: Genuine-looking e-Challan (Govt)",
    description:
      "A realistic e-Challan notification referencing the official portal. Should return Likely Genuine or Unable to Verify.",
    inputType: "text",
    expectedVerdict: "Likely Genuine",
    badge: "SYNTHETIC TEST CASE — NOT A REAL NOTICE",
    content: `Traffic Challan Notice - Ministry of Road Transport & Highways

Dear Vehicle Owner,

A traffic challan has been issued against your vehicle (DL 01 AB 1234) for violation of Rule 119(1) of CMVR — using mobile phone while driving.

Challan No: CH2024MH098765
Offence Date: 20-Sep-2024
Amount Due: Rs. 1,000/-
Due Date: 19-Oct-2024

You may pay this challan online at the official government portal:
https://echallan.parivahan.gov.in/

Alternatively, visit your nearest Traffic Court or RTO office.
No action is required if this challan has already been paid.

For queries, visit: https://parivahan.gov.in/
Ministry of Road Transport & Highways, Government of India`,
  },
  {
    id: "demo-lookalike",
    label: "Demo B: Fake Notice — Lookalike Domain",
    description:
      "A fraudulent message using a domain that resembles the official portal but is not. Should return Likely Fraudulent.",
    inputType: "text",
    expectedVerdict: "Likely Fraudulent",
    badge: "SYNTHETIC TEST CASE — NOT A REAL NOTICE",
    content: `URGENT: Traffic Challan Issued Against Your Vehicle

Dear Sir/Ma'am,

A traffic e-challan has been generated for your vehicle (MH 12 XY 9988).
Challan Amount: Rs. 2,000/-

Pay now to avoid LEGAL ACTION and driving licence suspension.

>> CLICK HERE TO PAY: http://echallan-parivahan-gov.xyz/pay?id=9988 <<

This is your FINAL NOTICE. Pay within 24 hours.

— Traffic Enforcement Cell, Mumbai`,
  },
  {
    id: "demo-apk",
    label: "Demo C: Fake Banking Alert — APK Download",
    description:
      "A fraudulent banking message requesting installation of a malicious APK file. Should return Likely Fraudulent.",
    inputType: "text",
    expectedVerdict: "Likely Fraudulent",
    badge: "SYNTHETIC TEST CASE — NOT A REAL NOTICE",
    content: `[Urgent] Your HDFC Bank Account is BLOCKED!

Dear Customer,
Your account ending in X4582 has been temporarily restricted due to suspicious login attempts.

To unblock and verify your KYC immediately, please download our Secure Banking App update:
http://hdfc-kyc-verify.ml/download/bank_update_v2.apk

Install the app, enter your PAN and verify securely.
Do not share this link with anyone.

Failure to verify within 24 hours will result in permanent account closure.`,
  },
  {
    id: "demo-urgent",
    label: "Demo D: Fake Notice — Urgent Payment Language",
    description:
      "A fraudulent message using extreme urgency and arrest threats. Should return Likely Fraudulent.",
    inputType: "text",
    expectedVerdict: "Likely Fraudulent",
    badge: "SYNTHETIC TEST CASE — NOT A REAL NOTICE",
    content: `FINAL LEGAL NOTICE — NON-BAILABLE WARRANT

Your vehicle (TN 22 AB 5566) has 3 unpaid challans totalling Rs. 8,500.
A non-bailable warrant has been issued against the registered owner.

You will be ARRESTED if payment is not made TODAY.

An FIR will be filed under Motor Vehicle Act if you do not respond immediately.

Pay immediately to avoid arrest: https://bit.ly/3fakechallan

This is your LAST CHANCE. Act now.

— Cyber Traffic Cell`,
  },
  {
    id: "demo-upi",
    label: "Demo E: Fake Notice — Suspicious UPI Request",
    description:
      "A fraudulent message containing a direct UPI VPA for payment, bypassing the official portal.",
    inputType: "text",
    expectedVerdict: "Likely Fraudulent",
    badge: "SYNTHETIC TEST CASE — NOT A REAL NOTICE",
    content: `Traffic Violation Notice

Vehicle: GJ 01 ZZ 2233
Challan Reference: RTOGJ20240918-44521
Amount: Rs. 3,200

Your challan payment is overdue. To avoid your driving licence being suspended, please pay via UPI immediately.

UPI ID: traffic.challan@okaxis
Google Pay / PhonePe accepted.

Payment deadline: Today before 11:59 PM.
Penalty will double after the deadline.

After payment, send screenshot to WhatsApp: +91-XXXXXXXXXX (verification team)

— Gujarat Traffic Police e-Challan Cell`,
  },
];
