from config import SUSPICIOUS_EXTENSIONS, LOG_DIR, COLUMNS_TO_DROP, SENSITIVE_LOCATIONS
import os 
import pandas as pd

SEVERITY_MAP = {
    'DEBUG': 0,
    'INFO': 1,
    'WARNING': 2,
    'CRITICAL': 3
}

def preprocessor(jsonl_path):
    df = load_events(jsonl_path)
    df = extract_features(df)
    return df


def load_events(jsonl_path):
    df = pd.read_json(jsonl_path, lines=True)
    return df

def extract_features(df):
    #timestamp processing
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    #pulling out specific info
    df['day'] = df['timestamp'].dt.day
    df['hour'] = df['timestamp'].dt.hour
    df['minute'] = df['timestamp'].dt.minute
    df['second'] = df['timestamp'].dt.second

    #event_type processing
    event_dummies = pd.get_dummies(df['event_type'], prefix='evt')
    df = pd.concat([df, event_dummies], axis=1)

    #severity processing
    df['severity_encoded'] = df['severity'].map(SEVERITY_MAP)
    df['severity_encoded'] = df['severity_encoded'].fillna(0).astype(int)

    #path processing
    analyzer = PathAnalyzer(SENSITIVE_LOCATIONS)
    location_features = df['path'].apply(analyzer.analyze)
    location_df = pd.DataFrame(location_features.tolist())
    df = pd.concat([df, location_df], axis=1)

    #extra dict processing
    df['extra_exe'] = df['extra'].apply(
        lambda x: x.get('exe') if isinstance(x, dict) else None
    )
    df['extra_pid'] = df['extra'].apply(
        lambda x: x.get('pid') if isinstance(x, dict) else None
    )
    df['extra_event_id'] = df['extra'].apply(
        lambda x: x.get('event_id') if isinstance(x, dict) else None
    )

    #filling NaN values
    df['sha256'] = df['sha256'].fillna('none')
    df['extra_pid'] = df['extra_pid'].fillna(0).astype(int)
    df['extra_event_id'] = df['extra_event_id'].fillna(0).astype(int)
    df['extra_exe'] = df['extra_exe'].fillna('')

    #removing columns 
    df = df.drop(columns=COLUMNS_TO_DROP, errors='ignore')

    return df

class PathAnalyzer:

    def __init__(self, sensitive_locations):
        self.locations = sensitive_locations

    def analyze(self, path):
        p = str(path).lower() if path else ''
        return {
            col: 1 if keyword in p else 0
            for col, keyword in self.locations.items()
        }