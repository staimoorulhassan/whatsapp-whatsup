content = open('src/whatsapp_client.py', 'r').read()

old = """    async def _wait_for_qr_code(self, timeout: int = 60) -> Optional[Any]:
        \"\"\"Wait for QR code to appear\"\"\"
        try:
            # Try multiple selectors - newer WhatsApp Web uses different patterns
            qr_selectors = [
                # New WhatsApp Web selectors
                'canvas[role="presentation"]',
                'img[alt="QR code"]',
                'img[alt*="Scan"]',
                '[data-testid="qrcode"]',
                '[data-testid="qr-code"]',
                # Legacy selectors
                'div[data-ref*="qr"]',
                '#qr',
                # Fallback: look for any canvas that might be the QR
                'div > canvas',
            ]

            for selector in qr_selectors:
                try:
                    element = await self.page.wait_for_selector(
                        selector,
                        timeout=timeout // len(qr_selectors) + 5000
                    )
                    if element:
                        # Verify it's actually visible
                        if await element.is_visible():
                            return element
                except:
                    continue

            return None

        except Exception as e:
            console.print(f"Error waiting for QR code: {e}")
            return None"""

new = """    async def _wait_for_qr_code(self, timeout: int = 60) -> Optional[Any]:
        \"\"\"Wait for QR code to appear\"\"\"
        try:
            # Try multiple selectors - WhatsApp Web uses various patterns
            qr_selectors = [
                # Current WhatsApp Web (most reliable)
                '[data-testid="link-device-qr-code"] canvas',
                '[data-testid="link-device-qr-code"]',
                # Canvas-based QR
                'canvas[role="presentation"]',
                # Image-based QR
                'img[alt="QR code"]',
                'img[alt*="Scan"]',
                # Test ID variations
                '[data-testid="qrcode"]',
                '[data-testid="qr-code"]',
                '[data-testid="qr-code-canvas"]',
                # Legacy selectors
                'div[data-ref*="qr"]',
                '#qr',
                # Fallback: look for any canvas in the main app area
                '#app canvas',
            ]

            for selector in qr_selectors:
                try:
                    element = await self.page.wait_for_selector(
                        selector,
                        timeout=timeout // len(qr_selectors) + 8000
                    )
                    if element:
                        if await element.is_visible():
                            return element
                except:
                    continue

            return None

        except Exception as e:
            console.print(f"Error waiting for QR code: {e}", style="red")
            return None"""

content = content.replace(old, new)
open('src/whatsapp_client.py', 'w').write(content)
print('Done')
