import type { SignalRepository } from '../Types'
import type { ILogger } from './logger'
import { isJidUser, isLidUser } from '../WABinary'

/**
 * Apply WhatsApp's LID priority system to determine encryption identity
 * Based on whatsmeow's message.go:284-298
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

    // WhatsApp Priority System:
    
    // PRIORITY 1: Use LID from message metadata if available
    if (senderAlt && isLidUser(senderAlt)) {
        logger.debug({ sender, senderAlt }, 'Using LID from message metadata')
        encryptionJid = senderAlt
        shouldMigrate = true
        return { encryptionJid, shouldMigrate }
    }

    // PRIORITY 2: Check stored LID mapping
    try {
        const lidStore = repository.getLIDMappingStore()
        const storedLid = await lidStore.getLIDForPN(sender)
        
        if (storedLid) {
            logger.debug({ sender, storedLid }, 'Using stored LID mapping')
            encryptionJid = storedLid
            shouldMigrate = true
            return { encryptionJid, shouldMigrate }
        }
    } catch (error) {
        logger.error({ sender, error }, 'Failed to lookup LID mapping')
    }

    // PRIORITY 3: No LID found - use PN
    logger.debug({ sender }, 'No LID found - using PN')
    return { encryptionJid, shouldMigrate }
}

/**
 * Handle LID migration sync messages
 * Based on whatsmeow's message.go:750-751
 */
export async function handleLIDMigrationSync(
    encodedPayload: Uint8Array,
    repository: SignalRepository,
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