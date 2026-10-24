"""
download_dataset.py
Downloads the UCI Phishing Websites dataset and prepares it for training.
"""
import os, sys, urllib.request, zipfile, shutil
from pathlib import Path

DATA_DIR = Path("data")
OUTPUT_CSV = DATA_DIR / "phishing_dataset.csv"
UCI_URL = "https://archive.ics.uci.edu/static/public/327/phishing+websites.zip"

def reporthook(block_num, block_size, total_size):
    if total_size > 0:
        downloaded = block_num * block_size
        pct = min(100, downloaded * 100 // total_size)
        bar = "#" * (pct // 5) + "-" * (20 - pct // 5)
        print(f"\r  [{bar}] {pct}%", end="", flush=True)

def convert_arff_to_csv(arff_path, csv_path):
    import pandas as pd
    lines = arff_path.read_text(encoding='utf-8', errors='replace').splitlines()
    attr_names = []
    data_section = False
    rows = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith('%'):
            continue
        if line.lower().startswith('@attribute'):
            parts = line.split(None, 2)
            attr_names.append(parts[1].strip("'\""))
        elif line.lower() == '@data':
            data_section = True
        elif data_section:
            row = line.split(',')
            if len(row) == len(attr_names):
                rows.append(row)
    df = pd.DataFrame(rows, columns=attr_names)
    for col in df.columns:
        try:
            df[col] = pd.to_numeric(df[col])
        except Exception:
            pass
    df.to_csv(csv_path, index=False)
    print(f"  Saved {len(df)} rows with {len(df.columns)} columns.")
    if 'Result' in df.columns:
        print(f"  Class distribution:\n{df['Result'].value_counts().to_string()}")
    return True

def main():
    DATA_DIR.mkdir(exist_ok=True)
    if OUTPUT_CSV.exists():
        print(f"Dataset already exists at: {OUTPUT_CSV}")
        print("Delete it and re-run to re-download.")
        return

    print("PhishGuard - Dataset Downloader")
    print("=" * 50)
    zip_path = DATA_DIR / "phishing_websites.zip"

    print(f"Downloading UCI Phishing Websites dataset...")
    print(f"  URL: {UCI_URL}")
    try:
        urllib.request.urlretrieve(UCI_URL, zip_path, reporthook)
        print()
    except Exception as e:
        print(f"\nDownload failed: {e}")
        sys.exit(1)

    print("Extracting...")
    try:
        with zipfile.ZipFile(zip_path, 'r') as z:
            names = z.namelist()
            print(f"  Contents: {names}")
            arff_file = next((n for n in names if n.endswith('.arff') and 'Training' in n), None)
            if not arff_file:
                arff_file = next((n for n in names if n.endswith('.arff')), None)
            if arff_file:
                z.extract(arff_file, DATA_DIR)
                arff_path = DATA_DIR / arff_file
                print(f"  Converting {arff_file} -> phishing_dataset.csv ...")
                convert_arff_to_csv(arff_path, OUTPUT_CSV)
                arff_path.unlink(missing_ok=True)
            else:
                csv_file = next((n for n in names if n.endswith('.csv')), None)
                if csv_file:
                    z.extract(csv_file, DATA_DIR)
                    shutil.move(str(DATA_DIR / csv_file), str(OUTPUT_CSV))
                else:
                    print(f"ERROR: No ARFF or CSV found in ZIP. Contents: {names}")
                    sys.exit(1)
    except Exception as e:
        print(f"Extraction error: {e}")
        sys.exit(1)
    finally:
        if zip_path.exists():
            zip_path.unlink()

    if OUTPUT_CSV.exists():
        print()
        print("=" * 50)
        print("Dataset ready!")
        print(f"  File: {OUTPUT_CSV}")
        print()
        print("Train the model with:")
        print("  python train_model.py --dataset data/phishing_dataset.csv --target Result")
        print("=" * 50)
    else:
        print("ERROR: Dataset file not created.")
        sys.exit(1)

if __name__ == "__main__":
    main()
