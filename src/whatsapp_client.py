import asyncio
import json
import os
import time
from pathlib import Path
from typing import Optional, Dict, Any
from urllib.parse import urlparse
import base64
from io import BytesIO

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()


class WhatsAppClient:
    """
    WhatsApp Web Automation Module

    Core component for triggering STUN packet exchange by:
    - Automating WhatsApp Web connection via QR code
    - Handling login and session management
    - Initiating calls to target numbers
    - Managing call hanging up
    - Removing all rate limiting and delays for maximum speed
    """

    def __init__(self, session_dir: str = "sessions", headless: bool = False):
        self.session_dir = Path(session_dir)
        self.session_dir.mkdir(exist_ok=True)
        self.headless = headless

        self.browser = None
        self.context = None
        self.page = None

        self.playwright = None
        self.logged_in = False

        # Session persistence
        self.session_file = self.session_dir / "whatsapp_session.json"
        self.cookies_file = self.session_dir / "cookies.json"

    async def initialize(self) -> bool:
        """Initialize browser and prepare for WhatsApp Web"""
        try:
            from playwright.async_api import async_playwright, Page, Browser, BrowserContext
            self._page_type = Page
            self._browser_type = Browser
            self._context_type = BrowserContext

            self.playwright = await async_playwright().start()

            # Launch browser with optimized settings for speed
            launch_args = []
            if self.headless:
                launch_args = [
                    '--no-sandbox',
                    '--disable-setuid-sandbox',
                    '--disable-dev-shm-usage',
                ]
            else:
                launch_args = [
                    '--no-sandbox',
                    '--disable-setuid-sandbox',
                    '--disable-dev-shm-usage',
                    '--disable-web-security',
                    '--disable-features=IsolateOrigins,site-per-Process',
                ]

            self.browser = await self.playwright.chromium.launch(
                headless=self.headless,
                args=launch_args,
                channel=None
            )

            # Create context with session restoration if available
            context_options = {
                'viewport': {'width': 1280, 'height': 720},
                'java_script_enabled': True,
                'bypass_csp': True,
                'ignore_https_errors': True,
                'permissions': ['camera', 'microphone']
            }

            # Restore session if exists
            if self.session_file.exists():
                with open(self.session_file, 'r') as f:
                    user_data = json.load(f)
                    context_options['user_agent'] = user_data.get('user_agent')

            self.context = await self.browser.new_context(**context_options)

            # Restore cookies if available
            if self.cookies_file.exists():
                with open(self.cookies_file, 'r') as f:
                    cookies = json.load(f)
                    await self.context.add_cookies(cookies)

            self.page = await self.context.new_page()

            # Set up page with reasonable settings
            await self.page.emulate_media(media='screen')

            console.print("[green]\u2713[/green] Browser initialized successfully")
            return True

        except Exception as e:
            console.print(f"[red]\u2717[/red] Failed to initialize browser: {e}")
            return False

    async def connect(self) -> Dict[str, Any]:
        """
        Connect to WhatsApp Web.

        Returns:
            Dict with 'success' and 'method' keys on result.
        """
        try:
            if not self.page:
                init_result = await self.initialize()
                if not init_result:
                    return {"success": False, "error": "Browser initialization failed", "method": None}

            console.print("Navigating to WhatsApp Web...")
            await self.page.goto("https://web.whatsapp.com/",
                                wait_until="networkidle",
                                timeout=30000)

            # Wait for page to load completely
            await self.page.wait_for_load_state("networkidle")

            # Check if already logged in
            if await self._check_logged_in():
                console.print("[green]\u2713[/green] Already logged in to WhatsApp Web")
                self.logged_in = True
                await self._save_session()
                return {"success": True, "method": "session_restored", "error": None}

            # Wait for QR code
            qr_element = await self._wait_for_qr_code()
            if not qr_element:
                console.print("[yellow]![/yellow] QR code not found. May already be logged in.")
                if await self._check_logged_in():
                    self.logged_in = True
                    await self._save_session()
                    return {"success": True, "method": "session_restored", "error": None}
                return {"success": False, "error": "QR code not found and not logged in", "method": None}

            console.print("[cyan]QR Code detected. Scan with WhatsApp mobile app.[/cyan]")
            console.print("Waiting for QR code scan...")

            return {"success": True, "method": "qr_required", "error": None}

        except Exception as e:
            console.print(f"[red]\u2717[/red] Connection failed: {e}")
            return {"success": False, "error": str(e), "method": None}

    async def wait_for_login(self, timeout: int = 300) -> bool:
        """
        Wait for user to complete QR login.

        Returns:
            bool: True if login completed, False on timeout or error.
        """
        return await self._wait_for_login_completion(timeout=timeout)

    async def _wait_for_qr_code(self, timeout: int = 60) -> Optional[Any]:
        """Wait for QR code to appear"""
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
            return None

    async def _check_logged_in(self) -> bool:
        """Check if already logged in"""
        try:
            # Look for indicators of being logged in
            login_indicators = [
                '[data-testid="chat-list"]',
                '[data-testid="conversation-panel"]',
                '[aria-label="Chat list"]',
                '.app-wrapper.web',
                'div[title="New chat"]'
            ]

            for selector in login_indicators:
                try:
                    element = await self.page.query_selector(selector)
                    if element:
                        return True
                except:
                    continue

            return False

        except Exception:
            return False

    async def _wait_for_login_completion(self, timeout: int = 120) -> bool:
        """Wait for login to complete"""
        start_time = time.time()

        while time.time() - start_time < timeout:
            if await self._check_logged_in():
                return True

            await asyncio.sleep(0.5)  # Minimal sleep

        return False

    async def _save_session(self):
        """Save session data for persistence"""
        try:
            # Save user data
            user_agent = await self.page.evaluate("navigator.userAgent")
            with open(self.session_file, 'w') as f:
                json.dump({'user_agent': user_agent}, f)

            # Save cookies
            cookies = await self.context.cookies()
            with open(self.cookies_file, 'w') as f:
                json.dump(cookies, f)

            console.print("[green]\u2713[/green] Session saved successfully")

        except Exception as e:
            console.print(f"Warning: Could not save session - {e}")

    async def initiate_call(self, phone_number: str) -> bool:
        """
        Initiate a voice call to target number

        Args:
            phone_number: Target phone number in international format (e.g., "+1234567890")

        Returns:
            bool: True if call initiated successfully
        """
        try:
            if not self.logged_in:
                console.print("[red]Not logged in. Call connect() first.[/red]")
                return False

            console.print(f"Initiating call to {phone_number}...")

            # Format phone number for WhatsApp
            clean_number = ''.join(filter(str.isdigit, phone_number))
            if not phone_number.startswith('+'):
                phone_number = '+' + clean_number

            # Navigate to chat with target number
            chat_url = f"https://web.whatsapp.com/send?phone={clean_number}"
            await self.page.goto(chat_url, wait_until="networkidle", timeout=30000)

            # Wait for chat to load
            await self.page.wait_for_timeout(1000)

            # Try to find call button
            call_button = await self._find_call_button()

            if not call_button:
                console.print(f"[yellow]Could not find call button for {phone_number}. Number may not be registered.[/yellow]")
                return False

            # Click call button
            await call_button.click()
            await asyncio.sleep(0.5)  # Minimal wait for call initiation

            console.print(f"[green]\u2713[/green] Call initiated to {phone_number}")
            return True

        except Exception as e:
            console.print(f"[red]Failed to initiate call: {e}[/red]")
            return False

    async def _find_call_button(self, timeout: int = 10000) -> Optional[Any]:
        """Find call button in chat"""
        try:
            # Multiple selectors for call buttons - updated for current WhatsApp Web UI
            call_selectors = [
                '[data-testid="call-button"]',
                '[data-testid="voice-call-button"]',
                '[aria-label="Voice call"]',
                '[aria-label="Call"]',
                '[title="Voice call"]',
                '[title="Call"]',
                'span[data-icon="call"]',
                'span[data-icon="voice-call"]',
                'div[role="button"][data-testid*="call"]',
                'button[aria-label*="call"]',
                'button[aria-label*="Call"]',
            ]

            for selector in call_selectors:
                try:
                    element = await self.page.wait_for_selector(
                        selector,
                        timeout=timeout // len(call_selectors) + 2000
                    )
                    if element and await element.is_visible():
                        return element
                except:
                    continue

            return None

        except Exception:
            return None

    async def hang_up_call(self) -> bool:
        """
        Hang up any active call

        Returns:
            bool: True if call hung up successfully
        """
        try:
            # Look for hang up button
            hang_up_selectors = [
                '[data-testid="hang-up-button"]',
                '[aria-label="End call"]',
                '[title="End call"]',
                'span[data-icon="video-stop"]',
                'span[data-icon="call-stop"]',
                'div[role="button"][aria-label*="End"]'
            ]

            for selector in hang_up_selectors:
                try:
                    element = await self.page.query_selector(selector)
                    if element and await element.is_visible():
                        await element.click()
                        console.print("[green]\u2713[/green] Call terminated")
                        return True
                except:
                    continue

            console.print("[yellow]No active call found or hang up button not visible[/yellow]")
            return False

        except Exception as e:
            console.print(f"[red]Failed to hang up call: {e}[/red]")
            return False

    async def trigger_call_sequence(self, phone_number: str, duration: float = 2.0) -> Dict[str, Any]:
        """
        Trigger a call sequence to generate STUN traffic

        Args:
            phone_number: Target phone number
            duration: Duration in seconds to keep call active

        Returns:
            Dict with 'success' and 'error' keys
        """
        try:
            console.print(f"[bold]Triggering call sequence for {phone_number}[/bold]")

            # Initiate call
            init_result = await self.initiate_call(phone_number)
            if not init_result:
                return {"success": False, "error": "Failed to initiate call"}

            # Wait for specified duration (minimal)
            await asyncio.sleep(duration)

            # Hang up
            await self.hang_up_call()

            console.print(f"[green]\u2713[/green] Call sequence completed for {phone_number}")
            return {"success": True, "error": None}

        except Exception as e:
            console.print(f"[red]Call sequence failed: {e}[/red]")
            return {"success": False, "error": str(e)}

    async def cleanup(self):
        """Clean up resources"""
        try:
            if self.page:
                await self.page.close()
            if self.context:
                await self.context.close()
            if self.browser:
                await self.browser.close()
            if self.playwright:
                await self.playwright.stop()

            console.print("[green]\u2713[/green] Cleanup completed")

        except Exception as e:
            console.print(f"Cleanup error: {e}")


# Utility function for quick usage
async def trigger_whatsapp_call(phone_number: str, session_dir: str = "sessions") -> bool:
    """
    Quick utility to trigger a WhatsApp call

    Args:
        phone_number: Target phone number
        session_dir: Directory to store session data

    Returns:
        bool: True if successful
    """
    client = WhatsAppClient(session_dir=session_dir)

    try:
        connect_result = await client.connect()
        if connect_result.get("success"):
            call_result = await client.trigger_call_sequence(phone_number)
            return call_result.get("success", False)
        return False
    finally:
        await client.cleanup()
