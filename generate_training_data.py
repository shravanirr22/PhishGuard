"""
generate_training_data.py
Generates a URL-feature training dataset using our feature extractor
applied to known phishing and legitimate URLs.

This produces data/url_features_dataset.csv with our 22 features + label.
It also combines with any existing UCI dataset features that overlap.

Usage:
    python generate_training_data.py
"""

import csv
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from feature_extraction import extract_features, FEATURE_NAMES

DATA_DIR = Path("data")
OUTPUT_CSV = DATA_DIR / "url_features_dataset.csv"

# Known legitimate URLs (well-established, public sites)
LEGIT_URLS = [
    "https://www.google.com",
    "https://www.youtube.com",
    "https://www.facebook.com",
    "https://www.wikipedia.org",
    "https://www.amazon.com",
    "https://www.microsoft.com",
    "https://www.apple.com",
    "https://www.github.com",
    "https://www.linkedin.com",
    "https://www.twitter.com",
    "https://www.reddit.com",
    "https://www.netflix.com",
    "https://www.instagram.com",
    "https://www.stackoverflow.com",
    "https://www.bbc.com/news",
    "https://www.cnn.com",
    "https://www.nytimes.com",
    "https://www.theguardian.com",
    "https://www.dropbox.com",
    "https://www.spotify.com",
    "https://mail.google.com",
    "https://docs.google.com",
    "https://drive.google.com",
    "https://accounts.google.com/signin",
    "https://www.paypal.com",
    "https://www.ebay.com",
    "https://www.walmart.com",
    "https://www.bestbuy.com",
    "https://www.chase.com",
    "https://www.bankofamerica.com",
    "https://www.wellsfargo.com",
    "https://www.citibank.com",
    "https://www.irs.gov",
    "https://www.usa.gov",
    "https://www.cdc.gov/covid",
    "https://www.who.int",
    "https://www.python.org",
    "https://www.django.org",
    "https://www.flask.palletsprojects.com",
    "https://scikit-learn.org/stable",
    "https://www.kaggle.com",
    "https://www.coursera.org",
    "https://www.udemy.com",
    "https://www.w3schools.com",
    "https://developer.mozilla.org",
    "https://www.cloudflare.com",
    "https://aws.amazon.com",
    "https://azure.microsoft.com",
    "https://cloud.google.com",
    "https://www.heroku.com",
    "https://www.digitalocean.com",
    "https://www.stripe.com",
    "https://www.twilio.com",
    "https://www.salesforce.com",
    "https://www.zoom.us",
    "https://www.slack.com",
    "https://www.notion.so",
    "https://www.figma.com",
    "https://www.canva.com",
    "https://www.trello.com",
    "https://www.atlassian.com",
    "https://www.jira.atlassian.com",
    "https://www.hubspot.com",
    "https://www.mailchimp.com",
    "https://www.shopify.com",
    "https://www.wix.com",
    "https://www.squarespace.com",
    "https://www.wordpress.com",
    "https://www.medium.com",
    "https://www.quora.com",
    "https://www.yelp.com",
    "https://www.tripadvisor.com",
    "https://www.booking.com",
    "https://www.airbnb.com",
    "https://www.uber.com",
    "https://www.lyft.com",
    "https://www.doordash.com",
    "https://www.grubhub.com",
    "https://www.etsy.com",
    "https://support.apple.com",
    "https://help.twitter.com",
    "https://help.instagram.com",
    "https://www.adobe.com",
    "https://www.oracle.com",
    "https://www.ibm.com",
    "https://www.intel.com",
    "https://www.nvidia.com",
    "https://www.samsung.com",
    "https://www.sony.com",
    "https://www.hp.com",
    "https://www.dell.com",
    "https://www.lenovo.com",
    "https://www.target.com",
    "https://www.homedepot.com",
    "https://www.costco.com",
    "https://www.walgreens.com",
    "https://www.cvs.com",
    "https://www.fedex.com",
    "https://www.ups.com",
    "https://www.usps.com/tracking",
]

# Known phishing-style URLs (simulated malicious patterns)
PHISH_URLS = [
    "http://paypa1-secure-login.xyz/account/verify",
    "http://192.168.0.1/login/verify?token=abc&secure=1",
    "http://10.0.0.1/banking/login/account/update",
    "http://secure-bank-login.tk/verify/account",
    "http://bit.ly/3xPhish123",
    "http://tinyurl.com/fakebank-login",
    "http://www.google.com.fake-login.xyz/account",
    "http://paypal.com.secure-update.info/login",
    "http://amazon.suspicious-login.tk/signin",
    "http://microsoftsupport-alert.xyz/login/verify",
    "http://apple-id-suspended.xyz/verify/account",
    "http://facebook-login-security.xyz/checkpoint",
    "http://ebay-account-suspended.xyz/signin/verify",
    "http://netflix-update-payment.xyz/billing",
    "http://irs-refund-claim.xyz/refund/login",
    "http://your-bank-secure-login.xyz/login",
    "http://secure-account-update-now.xyz/login/verify",
    "http://login-verify-account.xyz/secure/update",
    "http://193.187.100.12/paypal/login.php",
    "http://172.16.254.1/chase/banking/login",
    "http://10.10.10.10/microsoft/account/verify",
    "http://login.paypal.com.secure-user.xyz/verify",
    "http://account.google.com.phish-site.tk/signin",
    "http://secure.amazon.com.fake-store.xyz/signin",
    "http://update-your-netflix-payment.xyz/update",
    "http://bank-of-america-secure.xyz/login/account",
    "http://wells-fargo-secure-login.xyz/banking",
    "http://chase-bank-verify.xyz/login/secure",
    "http://citibank-alert-security.xyz/verify",
    "http://apple-support-alert.tk/id/verify",
    "http://amazon@malicious-login.xyz/account",
    "http://support@phishing-example.com/helpdesk",
    "http://secure-login-bank-update-verify.xyz/account/login/update/verify/now",
    "http://free-gift-card-claim-now.xyz/login/verify",
    "http://lucky-winner-prize-claim.xyz/account/verify",
    "http://discount-coupons-free.tk/login",
    "http://your-account-suspended-verify.xyz/login",
    "http://unusual-activity-detected.xyz/verify/login",
    "http://alert-security-login-verify.xyz/account",
    "http://credential-update-required.xyz/login",
    "http://click-here-to-verify.xyz/account/update",
    "http://submit-your-credentials.xyz/banking/login",
    "http://user-account-billing.xyz/update/payment",
    "http://client-support-verify.xyz/login",
    "http://access-suspended-verify.xyz/account",
    "http://invoice-payment-due.xyz/submit/login",
    "http://ebay.com.suspended-seller.xyz/login",
    "http://password-reset-required.xyz/account/login",
    "http://webscr-login-submit.xyz/account",
    "http://signin-account-update.xyz/verify/now",
    "http://192.168.1.1:8080/admin/login.php",
    "http://10.0.0.1:9090/phishing/login",
    "http://login.secure-bank.xyz/verify?user=admin&password=test",
    "http://a.b.c.d.e.suspicious-domain.xyz/login/verify/account/secure",
    "http://www.paypal.login.secure.verify.xyz/signin",
    "http://google.com.login.update.verify.net/account",
    "http://apple.id.suspended.verification.xyz/login",
    "http://secure-paypal-login-verify-account.tk",
    "http://bank-login-secure-verify-update-now.xyz",
    "http://amazon-prime-free-trial-login.xyz/signin",
    "http://microsoft-account-alert.xyz/login/verify",
    "http://steam-free-game-login.xyz/account",
    "http://roblox-free-robux-login.xyz/account",
    "http://fortnite-vbucks-free.xyz/login",
    "http://crypto-wallet-login-verify.xyz/account",
    "http://binance-secure-login.xyz/verify",
    "http://coinbase-account-suspended.xyz/login",
    "http://tax-refund-login-verify.xyz/irs/refund",
    "http://social-security-login.xyz/verify/account",
    "http://medicare-login-update.xyz/account/verify",
    "http://fedex-delivery-update.xyz/track/login",
    "http://ups-delivery-alert.xyz/track/verify",
    "http://usps-package-held.xyz/verify/account",
    "http://dhl-shipment-login.xyz/track/update",
    "http://login-facebook.xyz/checkpoint/verify",
    "http://instagram-verify-account.xyz/login",
    "http://twitter-suspend-verify.xyz/account",
    "http://linkedin-account-warning.xyz/verify",
    "http://zoom-login-verify.xyz/account/signin",
    "http://dropbox-shared-file.xyz/login/view",
    "http://docusign-sign-here.xyz/login/document",
    "http://office365-login-verify.xyz/account",
    "http://outlook-security-alert.xyz/verify/login",
    "http://sharepoint-login-secure.xyz/account",
    "http://onedrive-shared-file.xyz/view/login",
    "http://netflix-billing-update.xyz/account",
    "http://hulu-payment-due.xyz/update/billing",
    "http://disneyplus-login-verify.xyz/account",
    "http://spotify-premium-free.xyz/login/verify",
    "http://free-antivirus-download.xyz/login",
    "http://your-computer-infected.xyz/support/login",
    "http://tech-support-alert.xyz/verify/microsoft",
    "http://virus-detected-click-here.xyz/remove",
    "http://win-prize-enter-now.xyz/login/claim",
    "http://survey-reward-cash.xyz/login/verify",
    "http://investment-return-guaranteed.xyz/login",
    "http://crypto-profit-login.xyz/account/verify",
    "http://online-job-login.xyz/account",
    "http://work-from-home-earn.xyz/login",
]


def main():
    DATA_DIR.mkdir(exist_ok=True)

    if OUTPUT_CSV.exists():
        print(f"Dataset already exists: {OUTPUT_CSV}")
        print("Delete it and re-run to regenerate.")
        return

    print("Generating URL features dataset...")
    rows = []

    # Process legitimate URLs
    legit_ok, legit_err = 0, 0
    for url in LEGIT_URLS:
        try:
            f = extract_features(url)
            f["label"] = 0  # legitimate
            rows.append(f)
            legit_ok += 1
        except Exception as e:
            legit_err += 1

    print(f"  Legitimate: {legit_ok} OK, {legit_err} errors")

    # Process phishing URLs
    phish_ok, phish_err = 0, 0
    for url in PHISH_URLS:
        try:
            f = extract_features(url)
            f["label"] = 1  # phishing
            rows.append(f)
            phish_ok += 1
        except Exception as e:
            phish_err += 1

    print(f"  Phishing  : {phish_ok} OK, {phish_err} errors")

    # Write CSV
    fieldnames = FEATURE_NAMES + ["label"]
    with open(OUTPUT_CSV, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    total = len(rows)
    print(f"\nDataset saved: {OUTPUT_CSV}")
    print(f"  Total samples : {total}")
    print(f"  Legitimate    : {legit_ok}")
    print(f"  Phishing      : {phish_ok}")
    print()
    print("NOTE: This is a small handcrafted dataset for demonstration.")
    print("For best results, use a large real-world dataset like UCI Phishing Websites.")
    print()
    print("Train the aligned model with:")
    print("  python train_model.py --dataset data/url_features_dataset.csv --target label")


if __name__ == "__main__":
    main()
