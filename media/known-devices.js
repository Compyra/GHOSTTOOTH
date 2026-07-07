/* ============================================================
   Curated known-device database for the GHOSTTOOTH scanner
   (loaded before script.js as a classic script).

   Unlike SURVEILLANCE_COMPANIES / TRACKER_COMPANIES in script.js
   (Bluetooth SIG manufacturer IDs — safe to key off because they
   identify the *product maker*), many single-purpose devices only
   ever advertise a generic silicon vendor's MFR ID (Nordic
   Semiconductor, Espressif, Dialog/Renesas, STMicro, TI, ...) that
   is shared by thousands of unrelated products. Those IDs must
   NEVER be used for classification on their own — instead, add an
   entry here keyed by a device-name pattern for anything found in
   the wild that the generic rules in script.js don't already catch.
   ============================================================ */

'use strict';

/**
 * Devices identified by name/model that generic MFR-ID or built-in
 * name-pattern rules in script.js do not catch. Each entry:
 *   { pattern: RegExp, type: 'surveillance'|'tracker', reason: string }
 */
const KNOWN_DEVICE_NAME_PATTERNS = [
    // PLAUD_NOTE / PLAUD NotePin only advertise MFR ID 0x0059 (Nordic
    // Semiconductor — a generic BLE chipset used by countless unrelated
    // products), so it can only be recognized by name.
    { pattern: /plaud/i, type: 'surveillance', reason: 'PLAUD Note / NotePin — wearable AI voice recorder' },
];
