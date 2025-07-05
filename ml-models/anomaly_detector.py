"""
Anomaly Detection Module for Network Packet Analysis
Implements multiple ML algorithms for detecting network anomalies 
"""
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.decomposition import PCA
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import logging
from datetime import datetime, timedelta
import json
import redis
from typing import Dict, List, Tuple, Optional
from sklearn.cluster import DBSCAN
import warnings
warnings.filterwarnings('ignore')

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class NetworkAnomalyDetector:
    """
    Multi-algorithm anomaly detection system for network traffic analysis
    """

    def __init__(self, config_path: Optional[str] = None):
        self.config = self._load_config(config_path)
        self.models = {}
        self.scalers = {}
        self.features_columns = []
        self.redis_client = None
        self._setup_redis()

    def _load_config(self, config_path: Optional[str]) -> Dict:
        """Load configuration from files or use defaults"""
        default_config = {
            'isolation_forest': {
                'contamination': 0.1,
                'n_estimators': 100,
                'max_samples': 'auto',
                'random_state': 42
            },
            'dbscan': {
                'eps': 0.5,
                'min_samples': 5,
                'metric': 'euclidean',
            },
            'pca': {
                'n_components': 0.95,
                'random_state': 42,
            },
            'thresholds': {
                'packet_rate_threshold': 1000,
                'byte_rate_threshold': 1000000,
                'connection_threshold': 100,
                'port_scan_threshold': 20,
            },
            'redis': {
                'host': 'localhost',
                'port': 6379,
                'db': 0,
                'password': None,
            }
        }
        if config_path is not None: 
            try:
                with open(config_path, 'r') as f:
                    loaded_config = json.load(f)
                    default_config.update(loaded_config)
            except Exception as e:
                logger.warning(f"Could not load config from {config_path}: {e}")
        return default_config
    
    def _setup_redis(self):
        """Setup Redis connection for real-time data"""
        try:
            self.redis_client = redis.Redis(
                host=self.config['redis']['host'],
                port=self.config['redis']['port'],
                db=self.config['redis']['db'],
                password=self.config['redis']['password'],
                decode_responses=True
            )
            self.redis_client.ping()
            logger.info("Redis connection established")
        except Exception as e:
            logger.warning(f"Redis connection failed: {e}")
            self.redis_client = None

    def extract_features(self, packets_df: pd.DataFrame) -> pd.DataFrame:
        """Extract features from packet data for anomaly detection"""
        features = pd.DataFrame()

        try: 
            # Basic packet features
            features['packet_size'] = packets_df['length']
            features['protocol'] = pd.Categorical(packets_df['protocol']).codes
            features['src_port'] = packets_df['src_port'].fillna(0)
            features['dst_port'] = packets_df['dst_port'].fillna(0)

            # Temporal features
            packets_df['timestamp'] = pd.to_datetime(packets_df['timestamp'])
            features['hour'] = packets_df['timestamp'].dt.hour
            features['day_of_week'] = packets_df['timestamp'].dt.day_of_week

            # Traffic volume features (per minute windows)
            packets_df['minute'] = packets_df['timestamp'].dt.floor('min')
            minutes_stats = packets_df.groupby('minute').agg({
                'length': ['count', 'sum', 'mean', 'std'],
                'src_ip': 'nunique',
                'dst_ip': 'nunique',
                'src_port': 'nunique',
                'dst_port': 'nunique',
            }).fillna(0)

            # Flatten column names
            minutes_stats.columns = ['_'.join(col).strip() for col in minutes_stats.columns]

            # Merge back to original dataframes
            packets_df = packets_df.merge(minutes_stats, on='minute', how='left')

            # Add aggregated features
            features['packets_per_minute'] = packets_df['length_count']
            features['bytes_per_second'] = packets_df['length_sum']
            features['avg_packet_size'] = packets_df['length_mean']
            features['packet_size_std'] = packets_df['length_std'].fillna(0)
            features['unique_src_ips'] = packets_df['src_ip_nunique']
            features['unique_dst_ips'] = packets_df['dst_ip_nunique']
            features['unique_src_ports'] = packets_df['src_port_nunique']
            features['unique_dst_ports'] = packets_df['dst_port_nunique']

            # Connection patterns
            features['port_diversity'] = features['unique_dst_ports'] / (features['packets_per_minute'] + 1)
            features['ip_diversity'] = features['unique_dst_ips'] / (features['packets_per_minute'] + 1)

            # Protocol distribution
            protocol_counts = packets_df.groupby('minute')['protocol'].value_counts().unstack(fill_value=0)
            for proto in protocol_counts.columns:
                features[f'proto_{proto}_ratio'] = protocol_counts[proto] / features['packets_per_minute']
            
            # Detect potential port scanning
            features['potential_port_scan'] = (features['unique_dst_ports'] > self.config['thresholds']['port_scan_threshold']).astype(int)

            # Fill Nan values
            features = features.fillna(0)

            # Store features columns for later use
            self.features_columns = features.columns.tolist()

            logger.info(f"Extracted {len(features.columns)} features from {len(packets_df)} packets")
            return features
        except Exception as e: 
            logger.error(f"Feature extraction failed: {e}")
            return pd.DataFrame()
        
    def train_models(self, features_df: pd.DataFrame, save_path: Optional[str] = None) -> Dict:
        """Train multiple anomaly detction models"""
        results = {}

        try: 
            # Prepare data
            scaler = StandardScaler()
            features_scaled = scaler.fit_transform(features_df)
            self.scalers['standard'] = scaler

            # MinMax scaler for DBSCAN
            minmax_scaler = MinMaxScaler()
            features_minmax = minmax_scaler.fit_transform(features_df)
            self.scalers['minmax'] = minmax_scaler

            # PCA for dimensionality reduction
            pca = PCA(n_components=self.config['pca']['n_components'], random_state=self.config['pca']['random_state'])
            features_pca = pca.fit_transform(features_scaled)
            self.scalers['pca'] = pca

            # 1. isolation FOrest
            logger.info("Training Isolation Forest...")
            iso_forest = IsolationForest(
                contamination=self.config['isolation_forest']['contamination'],
                n_estimators=self.config['isolation_forest']['n_estimators'],
                max_samples=self.config['isolation_forest']['max_samples'],
                random_state=self.config['isolation_forest']['random_state'],
                n_jobs=-1
            )
            iso_forest.fit(features_scaled)
            self.models['isolation_forest'] = iso_forest

            # 2. DBSCAN Clustering
            logger.info("Training DBSCAN...")
            dbscan = DBSCAN(
                eps=self.config['dbscan']['eps'],
                min_samples=self.config['dbscan']['min_samples'],
                metric=self.config['dbscan']['metric'],
                n_jobs=-1
            )
            dbscan_labels = dbscan.fit_predict(features_minmax)
            self.models['dbscan'] = dbscan

            # 3. Statistical thresholds
            logger.info("Computing statistical thresholds...")
            self.models['thresholds'] = {
                'packet_rate_95th': np.percentile(features_df['packets_per_minute'], 95),
                'byte_rate_95th': np.percentile(features_df['bytes_per_second'], 95),
                'port_diversity_95th': np.percentile(features_df['port_diversity'], 95),
                'ip_diversity_95th': np.percentile(features_df['ip_diversity'], 95),
            }

            # Evaluate models
            iso_predictions = iso_forest.predict(features_scaled)
            iso_anomalies = np.sum(iso_predictions == -1)

            dbscan_anomalies = np.sum(dbscan_labels == -1)

            results = {
                'isolation_forest': {
                    'anomalies_detected': iso_anomalies,
                    'anomaly_rate': iso_anomalies / len(features_df),
                    'n_components_pca': features_pca.shape[1]
                },
                'dbscan': {
                    'anomalies_detected': dbscan_anomalies,
                    'anomaly_rate': dbscan_anomalies / len(features_df),
                    'n_clusters': len(set(dbscan_labels)) - (1 if -1 in dbscan_labels else 0)
                },
                'thresholds': self.models['thresholds']
            }

            # Save models
            if save_path:
                self.save_models(save_path)

            logger.info("Model training completed successfully")
            return results
        except Exception as e:
            logger.error(f"Model training failed: {e}")
            return {}
    
    def detect_anomalies(self, features_df: pd.DataFrame) -> Dict: 
        """Detect anomalies using trained models"""
        if not self.models:
            raise ValueError("Models not trained. Please train models first.")

        try:
            # Scale features
            features_scaled = self.scalers['standard'].transform(features_df)
            features_minmax = self.scalers['minmax'].transform(features_df)

            anomalies = {
                'isolation_forest': [],
                'dbscan': [],
                'statistical': [],
                'combined': []
            }

            # Isolation Forest predictions
            if 'isolation_forest' in self.models:
                iso_pred = self.models['isolation_forest'].predict(features_scaled)
                anomalies['isolation_forest'] = (iso_pred == -1).astype(int)

            # DBSCAN predictions
            if 'dbscan' in self.models:
                dbscan_pred = self.models['dbscan'].fit_predict(features_minmax)
                anomalies['dbscan'] = (dbscan_pred == -1).astype(int)

            # Statistical threshold-based detection
            start_anomalies = np.zeros(len(features_df), dtype=bool)
            thresholds = self.models['thresholds']

            start_anomalies |= (features_df['packets_per_minute'] > thresholds['packet_rate_95th'])
            start_anomalies |= (features_df['bytes_per_second'] > thresholds['byte_rate_95th'])
            start_anomalies |= (features_df['port_diversity'] > thresholds['port_diversity_95th'])
            start_anomalies |= (features_df['ip_diversity'] > thresholds['ip_diversity_95th'])
            start_anomalies |= (features_df['potential_port_scan'] == 1) 

            anomalies['statistical'] = start_anomalies.astype(int)

            # Combined anomaly score (voting)
            combined_score = np.zeros(len(features_df))
            for method in ['isolation_forest', 'dbscan', 'statistical']:
                if len(anomalies[method]) > 0:
                    combined_score += anomalies[method]
            
            # Anomaly if at least 2 methods agree
            start_anomalies['combined'] = (combined_score >= 2).astype(int)

            # Calculate anomaly scores
            anomaly_score = {}
            if 'isolation_forest' in self.models:
                anomaly_score['isolation_forest'] = self.models['isolation_forest'].decision_function(features_scaled)

            return {
                'anomalies': anomalies,
                'score': anomaly_score,
                'summary': {
                    'total_samples': len(features_df),
                    'anomalies_isolation_forest': np.sum(anomalies['isolation_forest']),
                    'anomalies_dbscan': np.sum(anomalies['dbscan']),
                    'anomalies_statistical': np.sum(anomalies['statistical']),
                    'anomalies_combined': np.sum(anomalies['combined'])
                }
            }
        except Exception as e:
            logger.error(f"Anomaly detection failed: {e}")
            return {}
    
    def real_time_detection(self, packet_data: Dict) -> Dict:
        """Perform real-time anomaly detection on incoming packet data"""
        try:
            # Convert to DataFrame
            df = pd.DataFrame([packet_data])

            # Extract features
            features = self.extract_features(df)

            if features.empty: 
                return {'error': 'Features extraction failed'}

            # Detect anomalies
            results = self.detect_anomalies(features)

            # Store in Redis if available
            if self.redis_client:
                timestamp = datetime.now().isoformat()
                redis_key = f"anomaly:{timestamp}"
                redis_data = {
                    'timestamp': timestamp,
                    'packet_data': json.dumps(packet_data),
                    'anomaly_results': json.dumps(results['summary'])
                } 
                self.redis_client.hset(redis_key, mapping=redis_data)
                self.redis_client.expire(redis_key, 3600)  # Expire after 1 hour

            return results
        except Exception as e:
            logger.error(f"Real-time detection failed: {e}")
            return {'error': str(e)}
        
    
    def save_models(self, save_path: str):
        """Save trained models and scalers"""
        try:
            model_data = {
                'models': self.models,
                'scalers': self.scalers,
                'feature_columns': self.features_columns,
                'config': self.config
            }
            joblib.dump(model_data, save_path)
            logger.info(f"Models saved to {save_path}")
        except Exception as e:
            logger.error(f"Failed to save models: {e}")

    def load_models(self, load_path: str):
        """Load trained models and saclers"""
        try:
            model_data = joblib.load(load_path)
            self.models = model_data['models']
            self.scalers = model_data['scalers']
            self.features_columns = model_data['feature_columns']
            self.config = model_data['config']
            logger.info(f"Models loaded from {load_path}")
        except Exception as e:
            logger.error(f"Failed to load models: {e}")
    
    def get_anomaly_report(self, start_time: datetime, end_time: datetime) -> Dict:
        """
        Generate anomaly detection report for a time period
        """
        if not self.redis_client:
            return {'error': 'Redis not available'}
        
        try:
            # Get anomaly data from Redis
            pattern = "anomaly:*"
            keys = self.redis_client.keys(pattern)
            
            # Handle case where no keys are found or keys is None
            if not keys or len(keys) == 0:
                return {'message': 'No anomaly data found in Redis'}
            
            anomalies = []
            for key in keys:
                try:
                    # Skip if key is None or empty
                    if not key:
                        continue
                        
                    data = self.redis_client.hgetall(key)
                    
                    # Check if data exists - Redis returns empty dict if key doesn't exist
                    if not data:
                        continue
                    
                    # Skip if required fields are missing (data is already decoded as strings)
                    if 'timestamp' not in data or 'anomaly_results' not in data:
                        logger.warning(f"Missing required fields in Redis key {key}")
                        continue
                    
                    # Parse timestamp with error handling
                    try:
                        timestamp = datetime.fromisoformat(data['timestamp'])
                    except (ValueError, TypeError) as e:
                        logger.warning(f"Invalid timestamp format in key {key}: {data['timestamp']}")
                        continue
                    
                    # Parse JSON with error handling
                    try:
                        results = json.loads(data['anomaly_results'])
                    except (json.JSONDecodeError, TypeError) as e:
                        logger.warning(f"Invalid JSON in anomaly_results for key {key}: {e}")
                        continue
                    
                    # Check time range
                    if start_time <= timestamp <= end_time:
                        anomalies.append({
                            'timestamp': timestamp,
                            'results': results
                        })
                        
                except Exception as e:
                    logger.warning(f"Error processing Redis key {key}: {e}")
                    continue
            
            # Generate report
            total_anomalies = len(anomalies)
            if total_anomalies == 0:
                return {'message': 'No anomalies detected in the specified time period'}
            
            # Aggregate statistics
            method_counts = {}
            for anomaly in anomalies:
                for method, count in anomaly['results'].items():
                    if method != 'total_samples':
                        method_counts[method] = method_counts.get(method, 0) + count
            
            report = {
                'time_period': {
                    'start': start_time.isoformat(),
                    'end': end_time.isoformat()
                },
                'total_anomalies': total_anomalies,
                'method_breakdown': method_counts,
                'anomaly_timeline': [
                    {
                        'timestamp': a['timestamp'].isoformat(),
                        'anomalies': a['results']
                    } for a in sorted(anomalies, key=lambda x: x['timestamp'])
                ]
            }
            
            return report
            
        except Exception as e:
            logger.error(f"Failed to generate anomaly report: {e}")
            return {'error': str(e)}

        
        
def main():
    """Example usage of the NetworkAnomalyDetector"""

    # Initialize detector
    detector = NetworkAnomalyDetector()

    # Example packet Data
    sample_packets = pd.DataFrame({
        'timestamp': pd.date_range('2024-01-01', periods=1000, freq='1s'),
        'src_ip': np.random.choice(['192.168.1.1', '192.168.1.2', '10.0.0.1'], 1000),
        'dst_ip': np.random.choice(['192.168.1.100', '8.8.8.8', '1.1.1.1'], 1000),
        'src_port': np.random.randint(1024, 65535, 1000),
        'dst_port': np.random.choice([80, 443, 53, 22], 1000),
        'protocol': np.random.choice(['TCP', 'UDP', 'ICMP'], 1000),
        'length': np.random.normal(500, 200, 1000).astype(int)
    })

    # Add some anomalies
    sample_packets.loc[950:960, 'length'] = 5000   # Large packets
    #sample_packets.loc[970:980, 'dst_port'] = list(range(1000, 1010))   # Port scan
    sample_packets.loc[970:980, 'dst_port'] = np.arange(1000, 1010)

    try:
        # Extract features
        logger.info("Extracting features...")
        features = detector.extract_features(sample_packets)

        if not features.empty:
            # Train models
            logger.info("Training models...")
            training_results = detector.train_models(features)
            print("Training Results:", json.dumps(training_results, indent=2))

            # Detect anomalies
            logger.info("Detect anomalies...")
            detection_results = detector.detect_anomalies(features)
            print("Detection Results:", json.dumps(detection_results['summary'], indent=2))

            # Save models
            detector.save_models('anomaly_models.pkl') 
    except Exception as e:
        logger.error(f"Example execution failed: {e}")

if __name__ == "__main__":
    main()


## Key Features:
    # Multi-algorithm approach: Uses Isolation Forest, DBSCAN clustering, and statistical thresholds
    # Comprehensive feature extraction: Analyzes packet size, protocol distribution, temporal patterns, traffic volume, and connection patterns
    # Real-time detection: Processes individual packets as they arrive
    # Port scan detection: Identifies potential reconnaissance activity
    # Traffic anomaly detection: Spots unusual spikes in packet/byte rates
    # Redis integration: Stores anomaly results for historical analysis
    # Model persistence: Save/load trained models for reuse