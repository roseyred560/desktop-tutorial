# SafeURL — URL Safety Checker

**Project owner:** Aditi Kumari

SafeURL is a lightweight web application that checks a submitted web address for common warning signs and presents a simple result: green (fewer warning signs), orange (use caution), or red (high caution).

## Project description
Suspicious links can use misleading hostnames, shortened destinations, unusual URL patterns, or words that imitate account and payment workflows. SafeURL applies a small set of transparent, rule-based checks to the URL text and explains the findings in plain language.

**Important limitation:** SafeURL does not open or crawl the submitted website and does not query a live threat-intelligence database. Its result is a preliminary heuristic, not a guarantee that a URL is safe or malicious. HTTPS alone does not mean a website is trustworthy.

## Technologies used
- Python
- Flask
- HTML and CSS (embedded in the Python application)
- `urllib.parse`, `ipaddress`, and `re` from Python's standard library

## Dataset
No external dataset is required or bundled. The current version uses explicit rule lists and URL-string features rather than a trained model or dataset. Therefore, there is no dataset download link for this version. If a threat-intelligence feed or dataset is added later, document its source, licence, and update date here.

## Files
- `AditiKumari_SafeURL.py` — complete application code
- `requirements.txt` — Python dependency list
- `AditiKumari_ProjectReport.docx` — project documentation

## Setup and run
1. Install Python 3.10 or later.
2. Open a terminal in the project folder.
3. (Recommended) Create and activate a virtual environment:
   - Windows: `py -m venv .venv` then `.venv\Scripts\activate`
   - macOS/Linux: `python3 -m venv .venv` then `source .venv/bin/activate`
4. Install dependencies:
   ```bash
   python -m pip install -r requirements.txt
   ```
5. Start the application:
   ```bash
   python AditiKumari_SafeURL.py
   ```
6. Open `http://127.0.0.1:5000` in your browser.
7. To stop the server, return to the terminal and press `Ctrl+C`.

## Example checks
- `https://example.com` — usually shows fewer warning signs.
- `http://example.com` — HTTP warning is reported.
- A shortened URL or a long URL with account-related wording may receive a caution result depending on the rules.

Results can vary with the exact URL. Do not test by opening unknown links; paste the text only.

## GitHub upload
1. Create a new repository on GitHub.
2. Upload the three project files listed above (or push the project folder with Git).
3. Add the repository URL to your submission form. The repository URL shares the source files; it does not automatically host the running Flask website.
4. For a public live website, deploy the app separately to a Python-compatible hosting service and configure it securely.

## Safety and privacy
- The submitted URL text is processed by the local application.
- The app does not visit the submitted destination.
- Do not use this result as the only basis for security decisions.
- For real threat verification, integrate a reputable threat-intelligence API with appropriate credentials and privacy safeguards.

## Licence
Choose and add a licence before distributing this project publicly.
