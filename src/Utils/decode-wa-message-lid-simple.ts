import type { SignalRepository } from '../Types'
import type { ILogger } from './logger'
import { isJidUser, isLidUser } from '../WABinary'

/**
 * Determine encryption JID following whatsmeow's simple approach
 * Based on whatsmeow's message.go:284-298
 * 
 * Key principles:
 * 1. Use LID from message metadata immediately (no session checks)
 * 2. Otherwise check stored LID mapping
 * 3. Default to original sender
 * 4. Migration happens separately, not during JID determination
 */
export async function determineEncryptionJid(
    sender: string,
    senderAlt: string | undefined,
    repository: SignalRepository,
    logger: ILogger
): Promise<string> {
    // Skip LID logic for non-user JIDs or bots
    if (!isJidUser(sender) || sender.includes('bot')) {
        logger.debug({ sender }, 'Non-user or bot JID, using original')
        return sender
    }

    // PRIORITY 1: Use LID from message metadata (trust WhatsApp's addressing)
    if (senderAlt && isLidUser(senderAlt)) {
        logger.info({ 
            sender, 
            senderAlt,
            source: 'message_metadata'
        }, 'Using LID from message attributes')
        return senderAlt
    }

    // PRIORITY 2: Check stored LID mapping
    try {
        const lidStore = repository.getLIDMappingStore()
        const storedLid = await lidStore.getLIDForPN(sender)
        
        if (storedLid && isLidUser(storedLid)) {
            logger.info({ 
                sender, 
                storedLid,
                source: 'stored_mapping'
            }, 'Using LID from stored mapping')
            return storedLid
        }
    } catch (error) {
        logger.warn({ sender, error }, 'Failed to lookup LID mapping')
    }

    // DEFAULT: Use original sender (PN)
    logger.debug({ sender }, 'No LID found, using original PN')
    return sender
}

/**
 * Check if migration is needed based on whatsmeow's logic
 * Migration happens when:
 * 1. We have a LID from message metadata
 * 2. Or we found a stored LID mapping
 * 
 * This is separate from JID determination to avoid race conditions
 */
export function shouldMigrateSession(
    originalSender: string,
    encryptionJid: string,
    senderAlt: string | undefined
): boolean {
    // Don't migrate if same JID
    if (originalSender === encryptionJid) {
        return false
    }

    // Migrate if we have LID from message metadata
    if (senderAlt && isLidUser(senderAlt) && senderAlt === encryptionJid) {
        return true
    }

    // Migrate if we're using a stored LID
    if (isLidUser(encryptionJid) && isJidUser(originalSender)) {
        return true
    }

    return false
}