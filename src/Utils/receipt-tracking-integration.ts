import type { WAMessageKey } from '../Types'
import type { ILogger } from './logger'
import { ReceiptTimeoutTracker } from './receipt-timeout-tracker'
import { jidNormalizedUser, isJidUser } from '../WABinary'

/**
 * Integration helper for receipt timeout tracking in message sending
 */
export class ReceiptTrackingIntegration {
    private readonly tracker: ReceiptTimeoutTracker
    private readonly logger: ILogger

    constructor(
        logger: ILogger,
        resendCallback: (messageKey: WAMessageKey, targetDevices: string[]) => Promise<void>
    ) {
        this.logger = logger
        this.tracker = new ReceiptTimeoutTracker(logger, resendCallback)
    }

    /**
     * Start tracking receipt timeout for a sent message
     */
    trackMessageSent(
        messageKey: WAMessageKey, 
        targetJid: string, 
        participants?: string[]
    ): void {
        try {
            // Extract all target devices
            let targetDevices: string[] = []

            if (participants && participants.length > 0) {
                // Group message OR direct message with specific device list - track all provided devices
                targetDevices = participants
                this.logger.debug({
                    messageId: messageKey.id,
                    deviceCount: participants.length,
                    devices: participants
                }, 'Tracking specific devices for message receipt')
            } else {
                // Direct message without specific devices - track the main JID
                targetDevices = [targetJid]
                this.logger.debug({
                    messageId: messageKey.id,
                    targetJid,
                    fallbackMode: true
                }, 'Tracking fallback JID for direct message')
            }

            // All devices should be tracked for receipts
            // The message-send layer already filters out inappropriate devices
            const filteredDevices = targetDevices

            if (filteredDevices.length > 0) {
                this.logger.debug({
                    messageId: messageKey.id,
                    targetJid,
                    targetDevices: filteredDevices,
                    isGroup: !!participants
                }, 'Starting receipt timeout tracking')

                this.tracker.startTracking(messageKey, filteredDevices)
            }
        } catch (error: any) {
            this.logger.error({
                messageId: messageKey.id,
                targetJid,
                error: error?.message
            }, 'Failed to start receipt tracking')
        }
    }

    /**
     * Handle incoming receipt - mark device as acknowledged
     */
    handleReceipt(
        messageId: string,
        senderJid: string,
        receiptType: 'delivery' | 'read' | 'sender' | string
    ): void {
        // Only track delivery receipts (not read receipts)
        if (receiptType === 'delivery' || receiptType === '' || !receiptType) {
            this.tracker.markReceiptReceived(messageId, senderJid)
            
            this.logger.debug({
                messageId,
                senderJid,
                receiptType,
                stillTracking: this.tracker.isTracking(messageId)
            }, 'Receipt acknowledged from device')
        }
    }

    /**
     * Get tracking statistics
     */
    getStats() {
        return this.tracker.getTrackingStats()
    }

    /**
     * Stop tracking specific message (manual override)
     */
    stopTracking(messageId: string): void {
        if (this.tracker.isTracking(messageId)) {
            this.logger.debug({ messageId }, 'Manually stopping receipt tracking')
            // Note: ReceiptTimeoutTracker doesn't expose stopTracking publicly
            // This would require extending the API if needed
        }
    }

    /**
     * Shutdown tracking system
     */
    shutdown(): void {
        this.tracker.shutdown()
    }
}