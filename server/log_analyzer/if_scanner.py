import os
import numpy as np
import pandas as pd

from log_analyzer import isoForestModel as _mod

#obiectele antrenate pe train set
_ISO = _mod.iso_forest
_OHE = _mod.ohe
_SCALER = _mod.scaler

#statisticile pe care e antrenat
_TRAIN_URL_FREQ = _mod.url_freq_map
_TRAIN_UA_FREQ = _mod.ua_freq_map
_CAT_COLS = _mod.categorical_cols
_VALID_NUM = _mod.valid_numeric_cols

def run_scan(db) -> dict:
   #preia datele din db si ruleaza modelul pe date
    rows = db.execute(
        """
        SELECT log_id, timestamp, client_ip, http_method,
               request_path, status_code, user_agent, response_time_ms
        FROM activity_logs
        ORDER BY timestamp DESC
        LIMIT 2000
        """
    ).fetchall()
 
    if len(rows) < 100:
        return {"error": "not_enough_data", "count": len(rows)}
 
    df = pd.DataFrame(rows, columns=[
        "log_id", "timestamp", "client_ip", "http_method",
        "request_path", "status_code", "user_agent", "response_time_ms"
    ])
 
    df["request_path"] = df["request_path"].fillna("/").astype(str)
    df["user_agent"] = df["user_agent"].fillna(" ").astype(str)
    df["client_ip"] = df["client_ip"].fillna(" ").astype(str)
   
    #redenumire coloane
    df = df.rename(columns={
        "http_method": "field_a",
        "request_path": "field_b",
        
        "user_agent": "field_d",
        "response_time_ms": "field_e"
    })

    df["field_c"] = np.where(df["status_code"].isin([401, 403]), "BLOCK", "ALLOW")
    df["is_blocked"] = df["status_code"].isin([401, 403]).astype(int)
 
    #adaugare features
    df = _mod.add_features(
        df,
        _TRAIN_URL_FREQ, 
        _TRAIN_UA_FREQ
    )
 
    # ohe si fit transform antrenate din model
    cat_cols = _CAT_COLS
    enc_arr = _OHE.transform(df[cat_cols])
    enc_df = pd.DataFrame(enc_arr, columns=_OHE.get_feature_names_out(cat_cols), index=df.index)
    num_df = pd.DataFrame(_SCALER.transform(df[_VALID_NUM].fillna(0)), columns=_VALID_NUM, index=df.index)
    X = pd.concat([enc_df, num_df], axis=1)
 
    #utilizare model
    scores = _ISO.decision_function(X)
    #threshold default 0.00
    predict = np.where(scores < 0, -1, 1)
    
    df["if_score"] = scores
    df["is_anomaly"] = (predict == -1).astype(int)
 
    #rezultate pt dashboard
    anomalies = df[df["is_anomaly"] == 1].sort_values("if_score").head(100)
   
    anomaly_list = [
        {
            "log_id": str(r["log_id"]),
            "timestamp": r["timestamp"].isoformat() if pd.notna(r["timestamp"]) else None,
            "client_ip": str(r["client_ip"]),
            "http_method": str(r["field_a"]),
            "request_path": str(r["field_b"]),
            "status_code": int(r["status_code"]),
            "user_agent": str(r["field_d"]),
            "response_time_ms": float(r["field_e"]),
            "if_score": round(float(r["if_score"]), 5),
            "ioc_count": int(r["ioc_count"]),
            "is_blocked": int(r["is_blocked"])
        }
        for _, r in anomalies.iterrows()
    ]
 
    return {
        "total_scanned": int(len(df)),
        "anomalies_found": int(df["is_anomaly"].sum()),
        "anomalies": anomaly_list
    }

def retrain(archive_dir: str) -> dict:
    """
    apeleaza isoForestModel.retrain_from_parquet()
     inlocuieste metrici globale din if_scanner cu noile obiecte 
    urmatorul apel run foloseste modelul reantrenat
    """
    global _ISO, _OHE, _SCALER, _TRAIN_URL_FREQ, _TRAIN_UA_FREQ, _VALID_NUM
 
    result = _mod.retrain_from_parquet(archive_dir)
 
    if "error" in result:
        return result   #returneaza spre ruta eroarea practic
 
    _ISO = result["model"]
    _OHE = result["ohe"]
    _SCALER = result["scaler"]
    _TRAIN_URL_FREQ = result["url_freq_map"]
    _TRAIN_UA_FREQ = result["ua_freq_map"]
    _VALID_NUM = result["valid_numeric"]
 
    return {
        "status": "retrained",
        "train_rows": result["train_rows"],
        "test_rows": result["test_rows"],
        "anomaly_rate_pct": result["anomaly_rate_pct"],
        "archive_count": result["archive_count"]
    }
 