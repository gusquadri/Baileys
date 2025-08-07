import type { SignalRepository } from '../Types'
import type { ILogger } from './logger'
import { isJidUser, isLidUser } from '../WABinary'

// Simple in-memory cache for device LID compatibility (resets on restart)
const deviceLidCompatibilityCache = new Map<string, { capable: boolean; lastCheck: number; failures: number }>()
const COMPATIBILITY_CACHE_TTL = 30 * 60 * 1000 // 30 minutes
const MAX_LID_FAILURES = 3 // After 3 failures, assume device doesn't support LID

/**
 * Check if a device likely supports LID based on heuristics and failure history
 * Based on whatsmeow's device capability detection with caching
 */
async function isDeviceLIDCapable(
    sender: string, 
    repository: SignalRepository, 
    logger: ILogger
): Promise<boolean> {
    try {
        const deviceKey = sender.split('@')[0] || sender
        const now = Date.now()
        
        // Check cache first
        const cached = deviceLidCompatibilityCache.get(deviceKey)
        if (cached && (now - cached.lastCheck) < COMPATIBILITY_CACHE_TTL) {
            // If device has too many failures, consider it non-LID capable
            if (cached.failures >= MAX_LID_FAILURES) {
                logger.debug({ sender, failures: cached.failures }, 'Device marked as LID-incapable due to failures')
                return false
            }
            return cached.capable
        }
        
        const deviceId = sender.split(':')[1]?.split('@')[0] || '0'
        let capable = false
        
        // Device 0 (main device) often has legacy behavior - be conservative
        if (deviceId === '0') {
            // Check if we have any evidence of LID sessions for device 0
            const userPart = sender.split('@')[0]?.split(':')[0]
            if (!userPart) {
                capable = false
            } else {
                const lidStore = repository.getLIDMappingStore()
                const possibleLid = await lidStore.getLIDForPN(sender)
                
                if (possibleLid) {
                    // Check if device 0 specifically has LID session
                    const device0LidJid = possibleLid.replace(`:${deviceId}@lid`, '@lid') // Remove device part first
                    const device0HasLidSession = await lidStore.hasSession(`${device0LidJid.split('@')[0]}:0@lid`)
                    logger.debug({ sender, device0HasLidSession }, 'Device 0 LID capability check')
                    capable = device0HasLidSession
                } else {
                    capable = false
                }
            }
        } else {
            // Connected devices (1+) are more likely to support LID in newer WhatsApp versions
            const deviceNumber = parseInt(deviceId, 10)
            if (deviceNumber >= 1) {
                // Higher device IDs often indicate newer WhatsApp versions with LID support
                // But we should still validate session existence rather than assume
                logger.debug({ sender, deviceId, deviceNumber }, 'Connected device - checking LID compatibility')
                capable = true // Will be validated by session existence check later
            } else {
                capable = false
            }
        }
        
        // Update cache
        deviceLidCompatibilityCache.set(deviceKey, {
            capable,
            lastCheck: now,
            failures: cached?.failures || 0
        })
        
        return capable
    } catch (error) {
        logger.warn({ sender, error }, 'Device LID capability check failed')
        return false
    }
}

/**
 * Record a LID failure for device capability tracking
 */
export function recordLIDFailure(sender: string, logger: ILogger): void {
    try {
        const deviceKey = sender.split('@')[0] || sender
        const cached = deviceLidCompatibilityCache.get(deviceKey)
        const failures = (cached?.failures || 0) + 1
        
        deviceLidCompatibilityCache.set(deviceKey, {
            capable: failures < MAX_LID_FAILURES, // Mark incapable after max failures
            lastCheck: Date.now(),
            failures
        })
        
        if (failures >= MAX_LID_FAILURES) {
            logger.warn({ 
                sender, 
                failures,
                deviceId: sender.split(':')[1]?.split('@')[0] || '0' 
            }, 'Device marked as LID-incapable after repeated failures')
        } else {
            logger.debug({ sender, failures }, 'Recorded LID failure for device')
        }
    } catch (error) {
        logger.warn({ sender, error }, 'Failed to record LID failure')
    }
}

/**
 * Apply WhatsApp's LID priority system with device compatibility detection
 * Based on whatsmeow's message.go:284-298 and send.go:1178-1186
 * CRITICAL: Validates session existence AND device LID capability before using LID
 */
export async function determineLIDEncryptionJid(
    sender: string,
    senderAlt: string | undefined,
    repository: SignalRepository,
    logger: ILogger,
    meId?: string
): Promise<{ encryptionJid: string; shouldMigrate: boolean }> {
    // Default to original sender
    let encryptionJid = sender
    let shouldMigrate = false

    // Skip LID logic for non-user JIDs
    if (!isJidUser(sender) || sender.includes('bot')) {
        return { encryptionJid, shouldMigrate }
    }

    // Own device optimization
    if (meId) {
        const ownNumber = meId.split('@')[0]?.split(':')[0]
        const targetNumber = sender.split('@')[0]?.split(':')[0]
        if (ownNumber === targetNumber) {
            logger.debug({ sender }, 'Own device - using PN directly')
            return { encryptionJid, shouldMigrate }
        }
    }

    // Helper function to check session existence
    const hasSession = async (jid: string): Promise<boolean> => {
        try {
            const lidStore = repository.getLIDMappingStore()
            const sessionExists = await lidStore.hasSession(jid)
            logger.debug({ jid, sessionExists }, 'Session existence check')
            return sessionExists
        } catch (error) {
            logger.warn({ jid, error }, 'Failed to check session existence')
            return false
        }
    }

    // WhatsApp Priority System with Session Validation:
    
    // PRIORITY 1: Use LID from message metadata - check device capability first
    if (senderAlt && isLidUser(senderAlt)) {
        logger.debug({ sender, senderAlt }, 'Checking LID from message metadata')
        
        // Check device LID capability before proceeding
        const deviceSupportsLid = await isDeviceLIDCapable(sender, repository, logger)
        if (!deviceSupportsLid) {
            logger.info({ 
                sender, 
                senderAlt, 
                deviceId: sender.split(':')[1]?.split('@')[0] || '0'
            }, 'Device does not support LID - falling back to PN despite metadata')
            return { encryptionJid, shouldMigrate }
        }
        
        const hasLidSession = await hasSession(senderAlt)
        const hasPnSession = await hasSession(sender)
        
        if (hasLidSession) {
            logger.info({ 
                sender, 
                senderAlt, 
                deviceId: sender.split(':')[1]?.split('@')[0] || '0'
            }, 'Using LID from message metadata (session already exists)')
            encryptionJid = senderAlt
            shouldMigrate = false // Session already exists, no migration needed
            return { encryptionJid, shouldMigrate }
        } else if (hasPnSession) {
            logger.info({ 
                sender, 
                senderAlt, 
                deviceId: sender.split(':')[1]?.split('@')[0] || '0'
            }, 'LID from metadata needs migration - PN session exists, LID session missing')
            encryptionJid = senderAlt
            shouldMigrate = true // Migrate PN session to LID
            return { encryptionJid, shouldMigrate }
        } else {
            logger.warn({ 
                sender, 
                senderAlt, 
                deviceId: sender.split(':')[1]?.split('@')[0] || '0'
            }, 'Neither LID nor PN session exists - falling back to PN for session creation')
        }
    }

    // PRIORITY 2: Check stored LID mapping - validate device capability first
    try {
        const lidStore = repository.getLIDMappingStore()
        const storedLid = await lidStore.getLIDForPN(sender)
        
        if (storedLid) {
            logger.debug({ sender, storedLid }, 'Found stored LID mapping, checking device compatibility')
            
            // Check device LID capability before proceeding with stored mapping
            const deviceSupportsLid = await isDeviceLIDCapable(sender, repository, logger)
            if (!deviceSupportsLid) {
                logger.info({ 
                    sender, 
                    storedLid, 
                    deviceId: sender.split(':')[1]?.split('@')[0] || '0'
                }, 'Device does not support LID - ignoring stored mapping, using PN')
                return { encryptionJid, shouldMigrate }
            }
            
            const hasLidSession = await hasSession(storedLid)
            const hasPnSession = await hasSession(sender)
            
            if (hasLidSession) {
                logger.info({ 
                    sender, 
                    storedLid, 
                    deviceId: sender.split(':')[1]?.split('@')[0] || '0'
                }, 'Using stored LID mapping (session already exists)')
                encryptionJid = storedLid
                shouldMigrate = false // Session already exists, no migration needed
                return { encryptionJid, shouldMigrate }
            } else if (hasPnSession) {
                logger.info({ 
                    sender, 
                    storedLid, 
                    deviceId: sender.split(':')[1]?.split('@')[0] || '0'
                }, 'Stored LID mapping needs migration - PN session exists, LID session missing')
                encryptionJid = storedLid
                shouldMigrate = true // Migrate PN session to LID
                return { encryptionJid, shouldMigrate }
            } else {
                logger.warn({ 
                    sender, 
                    storedLid, 
                    deviceId: sender.split(':')[1]?.split('@')[0] || '0'
                }, 'LID mapping exists but neither LID nor PN session found - falling back to PN for session creation')
            }
        } else {
            logger.debug({ sender }, 'No stored LID mapping found')
        }
    } catch (error) {
        logger.error({ sender, error }, 'Failed to lookup LID mapping')
    }

    // PRIORITY 3: No LID found or migration not possible - use PN
    logger.info({ 
        sender, 
        deviceId: sender.split(':')[1]?.split('@')[0] || '0'
    }, 'No LID mapping found or migration not possible - using PN')
    return { encryptionJid, shouldMigrate }
}

/**
 * Handle LID migration sync messages
 * Based on whatsmeow's message.go:750-751
 */
export async function handleLIDMigrationSync(
    encodedPayload: Uint8Array,
    _repository: SignalRepository,
    logger: ILogger
): Promise<void> {
    try {
        logger.info({ payloadSize: encodedPayload.length }, 'Received LID migration sync message from server')
        
        // In a complete implementation:
        // 1. Decode proto.LIDMigrationMappingSyncPayload
        // 2. Extract pnToLidMappings array
        // 3. Store each mapping using repository.getLIDMappingStore().storeLIDPNMapping()
        // 4. Handle latestLid vs assignedLid for LID refresh
    } catch (error) {
        logger.error({ error }, 'Failed to process LID migration sync')
    }
}

/**
 * Check if we should recreate session after decryption failure
 * Based on whatsmeow's retry.go:126-137
 */
export function shouldRecreateSession(
    _jid: string,
    retryCount: number,
    hasSession: boolean,
    lastRecreationTime?: number
): { shouldRecreate: boolean; reason: string } {
    // No session exists - immediate recreation
    if (!hasSession) {
        return {
            shouldRecreate: true,
            reason: "we don't have a Signal session with them"
        }
    }

    // Need at least 2 retries before recreation
    if (retryCount < 2) {
        return {
            shouldRecreate: false,
            reason: 'retry count below threshold'
        }
    }

    // Check if enough time passed since last recreation (1 hour)
    const recreationTimeout = 60 * 60 * 1000
    if (!lastRecreationTime || Date.now() - lastRecreationTime > recreationTimeout) {
        return {
            shouldRecreate: true,
            reason: 'retry count > 1 and timeout expired'
        }
    }

    return {
        shouldRecreate: false,
        reason: 'recreation attempted recently'
    }
}