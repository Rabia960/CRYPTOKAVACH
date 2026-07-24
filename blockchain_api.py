"""
CryptoWatch Blockchain Transaction API
Simulates live blockchain data for BTC, ETH, USDT, LTC, XMR, DOGE, BNB
"""

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import random
import hashlib
import time
import math
from datetime import datetime, timedelta
import uvicorn

app = FastAPI(title="CryptoWatch Blockchain API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Helpers ────────────────────────────────────────────────────────────────

def seed_from_address(address: str) -> int:
    return int(hashlib.md5(address.encode()).hexdigest(), 16) % (2**31)

def fake_btc_txid():
    return hashlib.sha256(str(random.random()).encode()).hexdigest()

def fake_eth_txid():
    return "0x" + hashlib.sha256(str(random.random()).encode()).hexdigest()

def fake_address(coin: str) -> str:
    h = hashlib.md5(str(random.random()).encode()).hexdigest()
    if coin == "BTC":
        return "1" + h[:33]
    elif coin == "ETH":
        return "0x" + h[:40]
    elif coin == "LTC":
        return "L" + h[:33]
    elif coin == "XMR":
        return "4" + h[:94]
    elif coin == "DOGE":
        return "D" + h[:33]
    elif coin == "BNB":
        return "bnb1" + h[:38]
    else:
        return h[:40]

COIN_PRICES = {
    "BTC": 67420.0,
    "ETH": 3510.0,
    "USDT": 1.0,
    "LTC": 84.5,
    "XMR": 162.3,
    "DOGE": 0.162,
    "BNB": 608.0,
}

CRIME_RISK_LABELS = [
    "Ransomware Payment",
    "Darknet Market",
    "Mixer/Tumbler",
    "Scam",
    "Phishing",
    "Exchange Hack",
    "Terrorism Financing",
    "Human Trafficking",
    "Drug Trafficking",
    "Sanctions Evasion",
    "Clean",
    "Unknown",
]

def detect_coin(address: str) -> str:
    if address.startswith("0x") and len(address) == 42:
        return "ETH"
    elif address.startswith(("1", "3", "bc1")):
        return "BTC"
    elif address.startswith("L") or address.startswith("M"):
        return "LTC"
    elif address.startswith("4") and len(address) > 90:
        return "XMR"
    elif address.startswith("D"):
        return "DOGE"
    elif address.startswith("bnb"):
        return "BNB"
    else:
        return "BTC"

def generate_transactions(address: str, coin: str, count: int = 20, page: int = 1):
    rng = random.Random(seed_from_address(address) + page * 1000)
    transactions = []
    base_time = datetime.utcnow() - timedelta(days=rng.randint(30, 730))
    price = COIN_PRICES.get(coin, 1.0)

    for i in range(count):
        is_incoming = rng.random() > 0.45
        amount = round(rng.uniform(0.001, 50.0) if coin not in ("USDT",) else rng.uniform(100, 100000), 6)
        usd_value = round(amount * price, 2)
        fee = round(rng.uniform(0.00001, 0.005), 8)
        confirmations = rng.randint(1, 10000)
        tx_time = base_time + timedelta(hours=rng.randint(0, 720) * i // max(count, 1))

        risk_score = rng.randint(0, 100)
        if risk_score > 70:
            risk_label = rng.choice(CRIME_RISK_LABELS[:10])
            risk_level = "HIGH"
        elif risk_score > 40:
            risk_label = rng.choice(["Suspicious", "Unknown", "Mixer/Tumbler"])
            risk_level = "MEDIUM"
        else:
            risk_label = "Clean"
            risk_level = "LOW"

        counterparty = fake_address(coin)
        txid = fake_eth_txid() if coin == "ETH" else fake_btc_txid()

        transactions.append({
            "txid": txid,
            "block_height": rng.randint(500000, 850000),
            "timestamp": tx_time.isoformat() + "Z",
            "direction": "IN" if is_incoming else "OUT",
            "amount": amount,
            "coin": coin,
            "usd_value": usd_value,
            "fee": fee,
            "confirmations": confirmations,
            "counterparty_address": counterparty,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "risk_label": risk_label,
            "status": "CONFIRMED" if confirmations > 6 else "PENDING",
            "memo": rng.choice(["", "", "", "Payment", "Transfer", "Exchange Deposit", "Withdrawal"]),
        })

    transactions.sort(key=lambda x: x["timestamp"], reverse=True)
    return transactions


def generate_address_summary(address: str, coin: str):
    rng = random.Random(seed_from_address(address))
    price = COIN_PRICES.get(coin, 1.0)
    balance = round(rng.uniform(0, 100), 8)
    total_received = round(rng.uniform(balance, balance + 5000), 8)
    total_sent = round(total_received - balance, 8)
    tx_count = rng.randint(5, 500)
    first_seen = (datetime.utcnow() - timedelta(days=rng.randint(30, 2000))).isoformat() + "Z"
    last_seen = (datetime.utcnow() - timedelta(hours=rng.randint(0, 720))).isoformat() + "Z"
    risk_score = rng.randint(0, 100)

    return {
        "address": address,
        "coin": coin,
        "balance": balance,
        "balance_usd": round(balance * price, 2),
        "total_received": total_received,
        "total_received_usd": round(total_received * price, 2),
        "total_sent": total_sent,
        "total_sent_usd": round(total_sent * price, 2),
        "transaction_count": tx_count,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "risk_score": risk_score,
        "risk_level": "HIGH" if risk_score > 70 else "MEDIUM" if risk_score > 40 else "LOW",
        "cluster_size": rng.randint(1, 50),
        "exchange_exposure": round(rng.uniform(0, 100), 1),
        "darknet_exposure": round(rng.uniform(0, 60), 1),
        "mixer_exposure": round(rng.uniform(0, 40), 1),
    }


def generate_flow_graph(address: str, coin: str):
    rng = random.Random(seed_from_address(address) + 9999)
    nodes = [{"id": address, "label": address[:12] + "...", "type": "target", "risk": rng.randint(50, 100)}]
    edges = []

    num_inputs = rng.randint(2, 6)
    num_outputs = rng.randint(2, 5)

    for i in range(num_inputs):
        src = fake_address(coin)
        risk = rng.randint(0, 100)
        nodes.append({"id": src, "label": src[:12] + "...", "type": "source", "risk": risk})
        edges.append({
            "from": src,
            "to": address,
            "amount": round(rng.uniform(0.01, 10), 4),
            "coin": coin,
        })

    for i in range(num_outputs):
        dst = fake_address(coin)
        risk = rng.randint(0, 100)
        nodes.append({"id": dst, "label": dst[:12] + "...", "type": "destination", "risk": risk})
        edges.append({
            "from": address,
            "to": dst,
            "amount": round(rng.uniform(0.01, 10), 4),
            "coin": coin,
        })

    return {"nodes": nodes, "edges": edges}


# ─── Endpoints ───────────────────────────────────────────────────────────────

@app.get("/api/blockchain/address/{address}")
def get_address_info(address: str):
    coin = detect_coin(address)
    return generate_address_summary(address, coin)


@app.get("/api/blockchain/transactions/{address}")
def get_transactions(
    address: str,
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    direction: Optional[str] = Query(None),
    min_risk: Optional[int] = Query(None),
):
    coin = detect_coin(address)
    txs = generate_transactions(address, coin, count=limit, page=page)
    if direction in ("IN", "OUT"):
        txs = [t for t in txs if t["direction"] == direction]
    if min_risk is not None:
        txs = [t for t in txs if t["risk_score"] >= min_risk]
    return {
        "address": address,
        "coin": coin,
        "page": page,
        "limit": limit,
        "total_estimated": 200,
        "transactions": txs,
    }


@app.get("/api/blockchain/flow/{address}")
def get_flow_graph(address: str):
    coin = detect_coin(address)
    return generate_flow_graph(address, coin)


@app.get("/api/blockchain/risk/{address}")
def get_risk_profile(address: str):
    coin = detect_coin(address)
    rng = random.Random(seed_from_address(address) + 42)
    categories = {
        "Ransomware": round(rng.uniform(0, 30), 1),
        "Darknet Market": round(rng.uniform(0, 25), 1),
        "Mixer": round(rng.uniform(0, 20), 1),
        "Scam": round(rng.uniform(0, 15), 1),
        "Exchange": round(rng.uniform(0, 30), 1),
        "Clean": round(rng.uniform(10, 60), 1),
    }
    return {
        "address": address,
        "coin": coin,
        "overall_risk": rng.randint(0, 100),
        "categories": categories,
        "sanctions_match": rng.random() < 0.1,
        "pep_match": rng.random() < 0.05,
        "alerts": rng.randint(0, 5),
    }


@app.get("/api/blockchain/live-feed")
def get_live_feed(limit: int = Query(10, ge=1, le=50)):
    """Simulates a live mempool feed of suspicious transactions."""
    coins = ["BTC", "ETH", "USDT", "LTC", "XMR", "DOGE", "BNB"]
    feed = []
    for _ in range(limit):
        coin = random.choice(coins)
        risk = random.randint(60, 100)
        amount = round(random.uniform(0.1, 500), 4)
        price = COIN_PRICES.get(coin, 1.0)
        feed.append({
            "txid": fake_eth_txid() if coin == "ETH" else fake_btc_txid(),
            "coin": coin,
            "from_address": fake_address(coin),
            "to_address": fake_address(coin),
            "amount": amount,
            "usd_value": round(amount * price, 2),
            "risk_score": risk,
            "risk_label": random.choice(CRIME_RISK_LABELS[:10]),
            "timestamp": datetime.utcnow().isoformat() + "Z",
        })
    return {"feed": feed, "fetched_at": datetime.utcnow().isoformat() + "Z"}


@app.get("/health")
def health():
    return {"status": "ok", "service": "CryptoWatch Blockchain API"}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001)
