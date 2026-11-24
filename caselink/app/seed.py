"""Synthetic demo data. Everything here is invented; the 'APKs' are tiny ZIP files with no executable code."""
import io
import zipfile

TEXT_COMPLAINTS = [
    ("SBI KYC SMS", "Got SMS: Your SBI account will be blocked today. Update KYC at http://sbi-kyc-update.top/login and pay Rs 10 verification to refund.desk77@ybl"),
    ("WhatsApp fake app", "WhatsApp message from 9000011122 asked me to install SBI Rewards app from https://sbi-rewards-claim.xyz/app.apk, said KYC is pending."),
    ("Electricity threat call", "Caller said electricity will be disconnected tonight. Sent link http://sbi-kyc-verify.top/otp (also http://103.21.58.44/verify) and asked me to send money to refund.desk77@ybl"),
    ("Card details page", "Link https://sbi-rewards-claim.xyz/claim asked for card number and CVV. Number 9000011122 called me twice and told me to pay Rs 10 to refund.desk77@ybl"),
    ("Netbanking clone", "A fake bank page at http://103.21.58.44/sbi-login asked for my netbanking password."),
    ("Parcel fee scam", "Parcel customs fee: http://indiapost-delivery-fee.click/pay asked me to pay UPI customs.help21@paytm, call back 9000099887."),
    ("India Post SMS", "Message: your India Post parcel is held. Pay 45 at https://indiapost-delivery-fee.click/track or UPI customs.help21@paytm"),
    ("Gift voucher", "Amazon gift voucher link http://amaz0n-gift-claim.live/claim promised a reward if I log in."),
    ("Legitimate bank notice", "Received a maintenance notice that pointed to https://www.sbi.co.in, asking if it is genuine."),
]


def make_demo_apk(permissions: list[str], strings: list[str]) -> bytes:
    manifest = "<manifest>" + "".join(f'<uses-permission android:name="android.permission.{p}"/>' for p in permissions) + "</manifest>"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("AndroidManifest.xml", manifest)
        z.writestr("classes.dex", "dex\n035\0" + "\0".join(strings))
    return buf.getvalue()


DEMO_APKS = [
    ("SBI_Rewards.apk", make_demo_apk(
        ["READ_SMS", "RECEIVE_SMS", "BIND_ACCESSIBILITY_SERVICE", "SYSTEM_ALERT_WINDOW", "INTERNET"],
        ["https://api.telegram.org/bot123456789:AAFakeDemoTokenOnly/sendMessage", "refund.desk77@ybl", "AccessibilityService", "SmsManager"])),
    ("KYC_Update.apk", make_demo_apk(
        ["READ_SMS", "RECEIVE_SMS", "READ_CONTACTS", "REQUEST_INSTALL_PACKAGES"],
        ["https://api.telegram.org/bot123456789:AAFakeDemoTokenOnly/sendDocument", "DexClassLoader", "SmsManager"])),
]


def load_demo(store):
    from .pipeline import analyze_apk, analyze_text
    store.reset()
    for label, text in TEXT_COMPLAINTS:
        store.add(label, analyze_text(text))
    for name, data in DEMO_APKS:
        store.add(name, analyze_apk(name, data))
    return len(TEXT_COMPLAINTS) + len(DEMO_APKS)
