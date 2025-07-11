import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestRegressor, GradientBoostingRegressor
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import mean_squared_error, mean_absolute_error, r2_score
import joblib
import logging
from datetime import datetime, timedelta
import asyncio
import aioredis
from typing import Dict, List, Tuple, Optional
import json
import warnings
warnings.filterwarnings('ignore')

class PerformancePredictor:
    """
    ML-based network performance predictor for latency, throughput, and packet loss prediction.
    Uses ensemble methods to predict network performance metrics based on historical data.
    """
    def __init__(self, redis_host: str = 'localhost', redis_port: int = 6379):
        self.redis_host = redis_host
        self.redis_port = redis_port
        self.redis_client = None

        # Initialize models
        self.latency_model = None
        self.throughout_model = None
        self.packet_loss_model = None

        # features scalers
        self.scaler = StandardScaler()
        self.label_encoders = {}

        # features importance tracking
        self.feature_importance = {}

        # setup logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)

        # Model Parameters
        self.rf_params = {
            'n_estimators': 100,
            'max_depth': 20,
            'min_samples_split': 5,
            'min_samples_leaf': 2,
            'random_state': 42
        }

        self.gb_params = {
           'n_estimators': 100,
            'max_depth': 8,
            'learning_rate': 0.1,
            'random_state': 42
        }

    async def initialize_redis(self):
        """Initialize Redis connection for real-time data"""
        try:
            self.redis_client = await aioredis.from_url(
                f"redis://{self.redis_host}:{self.redis_port}",
                decode_responses = True
            )
            self.logger.info("Redis connection established")
        except Exception as e:
            self.logger.error(f"Failed to connect to Redis: {e}")
            raise 

    def extract_features(self, packet_data: Dict) -> np.ndarray:
        """
         Extract relevant features from packet data for performance prediction.
        Args:
            packet_data: Dictionary containing packet information
        Returns:
            Feature vector as numpy array
        """
        features = []
        # Time-based features
        timestamp = packet_data.get('timestamp', datetime.now().timestamp())
        dt = datetime.fromtimestamp(timestamp)
        features.extend([
            dt.hour,
            dt.day,
            dt.weekday(),
            dt.month
        ])

        # traffic volume features
        features.extend([
            packet_data.get('packet_count', 0),
            packet_data.get('byte_count', 0),
            packet_data.get('packets_per_second', 0),
            packet_data.get('bytes_per_second', 0)
        ])

        # Protocol distribution 
        protocols = packet_data.get('protocols', {})
        for protocol in ['tcp', 'udp', 'icmp', 'http', 'https', 'dns', 'ftp']:
            features.append(protocols.get(protocol, 0))
        
        # connection features
        features.extend([
            packet_data.get('unique_score', 0),
            packet_data.get('unique_distribution', 0),
            packet_data.get('active_connections', 0),
            packet_data.get('new_connections', 0)
        ])

        # port usage
        features.extend([
            packet_data.get('well_known_ports', 0),
            packet_data.get('registered_ports', 0),
            packet_data.get('dynamic_ports', 0)
        ])

        # QoS indicators
        features.extend([
            packet_data.get('dscp_marking', 0),
            packet_data.get('tos_field', 0),
            packet_data.get('priority_traffic', 0)
        ])

        # network topology features
        features.extend([
            packet_data.get('subnet_diversity', 0),
            packet_data.get('geographic_spread', 0),
            packet_data.get('hop_count_avg', 0)
        ])

        # historical performance features
        features.extend([
            packet_data.get('prev_latency', 0),
            packet_data.get('prev_throughout', 0),
            packet_data.get('prev_packet_loss', 0),
            packet_data.get('latency_trend', 0),
            packet_data.get('throughout_trend', 0)
        ])

        return np.array(features)
    
    def prepare_training_data(self, historical_data: List[Dict]) -> Tuple[np.ndarray, Dict[str, np.ndarray]]:
        """
        Prepare training data from historical network performance data.
        Args:
            historical_data: List of historical performance records   
        Returns:
            Tuple of (features, targets) where targets is a dict of metric arrays
        """
        features = []
        latency_targets = []
        throughput_targets = []
        packet_loss_targets = []

        for record in historical_data:
            # Extract features
            feature_vector = self.extract_features(record)
            features.append(feature_vector)

            # Extract targets
            latency_targets.append(record.get('latency_ms', 0))
            throughput_targets.append(record.get('throughout_mbps', 0))
            packet_loss_targets.append(record.get('packet_loss_percent', 0))

        X = np.array(features)
        y = {
            'latency': np.array(latency_targets),
            'throughput': np.array(throughput_targets),
            'packet_loss': np.array(packet_loss_targets)
        }

        return X, y
    
    def train_models(self, X: np.ndarray, y: Dict[str, np.ndarray]):
        """
        Train ensemble models for performance prediction.
        Args:
            X: Feature matrix
            y: Target dictionary with latency, throughput, and packet_loss arrays
        """
        # Scale features
        X_scaled = self.scaler.fit_transform(X)

        # Train latency prediction model
        self.logger.info("Training latency prediction model...")
        latency_model = GradientBoostingRegressor(**self.gb_params)
        latency_model.fit(X_scaled, y['latency'])
        self.latency_model = latency_model

        # Train throughput prediction model
        self.logger.info("Training throughput prediction model...")
        throughput_model = RandomForestRegressor(**self.rf_params)
        throughput_model.fit(X_scaled, y['throughput'])
        self.throughput_model = throughput_model

        # Train packet loss prediction model
        self.logger.info("Trainig packet loss prediction model...")
        packet_loss_model = GradientBoostingRegressor(**self.gb_params)
        packet_loss_model.fit(X_scaled, y['packet_loss'])
        self.packet_loss_model = packet_loss_model

        # Store features importance
        self.feature_importance = {
            'latency': latency_model.feature_importances_,
            'throughput': throughput_model.feature_importances_,
            'packet_loss': packet_loss_model.feature_importances_
        }

        self.logger.info("Model training completed")

    def predict_performance(self, packet_data: Dict) -> Dict[str, float]:
        """Predict network performance metrics for given packet data.
        Args:
            packet_data: Current packet/traffic data
        Returns:
            Dictionary containing predicted latency, throughput, and packet loss"""
        if not all([self.latency_model, self.throughout_model, self.packet_loss_model]):
            raise ValueError("Models not trained. Call train_models() first.")
        
        # Extract and scale features
        features = self.extract_features(packet_data).reshape(1, -1)
        features_scaled = self.scaler.transform(features)

        # Make predictions
        latency_pred = self.latency_model.predict(features_scaled)[0]
        throughput_pred = self.throughout_model.predict(features_scaled)[0]
        packet_loss_pred = self.packet_loss_model.predict(features_scaled)[0]

        # Ensure predictions are within reasonable bounds
        latency_pred = max(0, latency_pred)
        throughput_pred = max(0, throughput_pred)
        packet_loss_pred = max(0, min(100, packet_loss_pred))

        return {
            'predicted_latency_ms': round(latency_pred, 2),
            'predicted_throughput_mbps': round(throughput_pred, 2),
            'predicted_packet_loss_percent': round(packet_loss_pred, 3),
            'prediction_timestamp': datetime.now().isoformat()
        }
    
    def predict_future_performance(self, current_data: Dict, horizon_minutes: int = 30) -> List[Dict]:
        """
        Predict performance metrics for future time periods.
        Args:
            current_data: Current network state
            horizon_minutes: Prediction horizon in minutes
            
        Returns:
            List of predictions for future time periods
        """
        predictions = []
        # Create future time points
        for i in range(1, horizon_minutes + 1):
            future_time = datetime.now() + timedelta(minutes=i)

            # Modify current data for future prediction
            future_data = current_data.copy()
            future_data['timestamp'] = future_time.timestamp()

            # Add trend-based adjustments
            trend_factor = 1 + (i * 0.01)    # Simple linear trend
            future_data['packets_per_second'] = current_data.get('packets_per_second', 0) * trend_factor
            future_data['bytes_per_second'] = current_data.get('bytes_per_second', 0) * trend_factor

            # Predict performance
            prediction = self.predict_performance(future_data)
            prediction['prediction_horizon_minutes'] = i
            predictions.append(prediction)
        
        return predictions
    
    def evaluate_models(self, X_test: np.ndarray, y_test: Dict[str, np.ndarray]) -> Dict:
        """
        Evaluate model performance on test data.
        Args:
            X_test: Test feature matrix
            y_test: Test target dictionary
        Returns:
            Dictionary containing evaluation metrics
        """
        X_test_scaled = self.scaler.transform(X_test)
        evaluation_results = {}

        for metric_name, model in [
            ('latency', self.latency_model),
            ('throughput', self.throughout_model),
            ('packet_loss', self.packet_loss_model)
        ]:
            y_pred = model.predict(X_test_scaled)
            y_true = y_test[metric_name]

            evaluation_results[metric_name] = {
                'mse': mean_squared_error(y_true, y_pred),
                'mae': mean_absolute_error(y_true, y_pred),
                'r2': r2_score(y_true, y_pred),
                'rmse': np.sqrt(mean_squared_error(y_true, y_pred))
            }
        return evaluation_results
    
    def detect_performance_anomalies(self, current_data: Dict, threshold_factor: float = 2.0) -> Dict:
        """
        Detect performance anomalies by comparing predictions with actual values.
        Args:
            current_data: Current network data including actual performance metrics
            threshold_factor: Factor for anomaly detection threshold 
        Returns:
            Dictionary indicating anomaly status for each metric
        """
        predictions = self.predict_performance(current_data)
        anomalies = {}

        # Check latency anomaly
        actual_latency = current_data.get('actual_latency_ms', 0),
        predicted_latency = predictions['predicted_latency_ms']
        latency_diff = abs(actual_latency - predicted_latency)
        anomalies['latency_anomaly'] = latency_diff > (predicted_latency * threshold_factor)

        # Check throughput anomaly
        actual_throughput = current_data.get('actual_throughput_mbps', 0)
        predicted_throughput = predictions['predicted_throughput_mbps']
        throughput_diff = abs(actual_throughput - predicted_throughput)
        anomalies['throughput_anomaly'] = throughput_diff > (predicted_throughput * threshold_factor)

        # check packet loss anomaly
        actual_packet_loss = current_data.get('actual_packet_loss_percent', 0)
        predicted_packet_loss = predictions['predicted_packet_losspercent']
        packet_loss_diff = abs(actual_packet_loss - predicted_packet_loss)
        anomalies['packet_loss_anomaly'] = packet_loss_diff > (predicted_packet_loss * threshold_factor)

        return anomalies

    async def continuous_predictions(self, interval_seconds: int = 60):
        """
        Continuously predict performance metrics and store results in Redis.
        Args:
            interval_seconds: Predictions interval in seconds
        """
        if not self.redis_client:
            await self.initialize_redis()

        while True:
            try:
                # Get current network data from Redis
                current_data_str = await self.redis_client.get('current_network_data')
                if current_data_str:
                    current_data = json.loads(current_data_str)

                    # Make predictions
                    predictions = self.predict_performance(current_data)

                    # Store predictions to Redis
                    await self.redis_client.set(
                        'performance_predictions',
                        json.dumps(predictions),
                        ex=3600                 # Expire after 1 hour
                    ) 

                    # Detection anomalies
                    anomalies = self.detect_performance_anomalies(current_data)
                    if any (anomalies.values()):
                        await self.redis_client.lpush('performance_anomalies', json.dumps(anomalies))

                    self.logger.info(f"Performance predictions completed: {predictions}")

                await asyncio.sleep(interval_seconds)
            
            except Exception as e:
                self.logger.error(f"Error in continuous prediction: {e}")
                await asyncio.sleep(interval_seconds)
    def save_models(self, model_path: str = './models'):
        """Save trained models to disk"""
        import os
        os.makedirs(model_path, exist_ok=True)

        joblib.dump(self.latency_model, f'{model_path}/latency_model.pkl')
        joblib.dump(self.throughout_model, f'{model_path}/throughput_model.pkl')
        joblib.dump(self.packet_loss_model, f'{model_path}/packet_loss_model.pkl')
        joblib.dump(self.scaler, f'{model_path}/scaler.pkl')

        self.logger.info(f"Model saved to {model_path}")

    def load_models(self, model_path: str = './models'):
        """Load trained models from disk"""
        self.latency_model = joblib.load(f'{model_path}/latency_model.pkl')
        self.throughout_model = joblib.load(f'{model_path}/throughput_model.pkl')
        self.packet_loss_model = joblib.load(f'{model_path}/packet_loss_model.pkl')
        self.scaler = joblib.load(f'{model_path}/scaler.pkl')

        self.logger.info(f"Models loaded from {model_path}")

# Example usage and testing
if __name__ == "__main__":
    # Initialize predictor
    predictor = PerformancePredictor()
    
    # Sample training data generation (replace with actual historical data)
    def generate_sample_data(n_samples: int = 1000) -> List[Dict]:
        """Generate sample network performance data for testing."""
        import random
        
        data = []
        for i in range(n_samples):
            # Generate synthetic network data
            packet_count = random.randint(100, 10000)
            byte_count = packet_count * random.randint(64, 1500)
            
            record = {
                'timestamp': (datetime.now() - timedelta(hours=random.randint(0, 720))).timestamp(),
                'packet_count': packet_count,
                'byte_count': byte_count,
                'packets_per_second': packet_count / 60,
                'bytes_per_second': byte_count / 60,
                'protocols': {
                    'tcp': random.randint(0, 100),
                    'udp': random.randint(0, 50),
                    'icmp': random.randint(0, 10),
                    'http': random.randint(0, 80),
                    'https': random.randint(0, 90),
                    'dns': random.randint(0, 20),
                    'ftp': random.randint(0, 5)
                },
                'unique_sources': random.randint(10, 500),
                'unique_destinations': random.randint(10, 1000),
                'active_connections': random.randint(50, 2000),
                'new_connections': random.randint(5, 200),
                'well_known_ports': random.randint(10, 100),
                'registered_ports': random.randint(5, 50),
                'dynamic_ports': random.randint(20, 200),
                'dscp_marking': random.randint(0, 63),
                'tos_field': random.randint(0, 255),
                'priority_traffic': random.randint(0, 20),
                'subnet_diversity': random.randint(1, 10),
                'geographic_spread': random.randint(1, 5),
                'hop_count_avg': random.randint(3, 20),
                'prev_latency': random.uniform(1, 200),
                'prev_throughput': random.uniform(1, 1000),
                'prev_packet_loss': random.uniform(0, 5),
                'latency_trend': random.uniform(-10, 10),
                'throughput_trend': random.uniform(-50, 50),
                # Target variables
                'latency_ms': random.uniform(1, 200),
                'throughput_mbps': random.uniform(1, 1000),
                'packet_loss_percent': random.uniform(0, 5)
            }
            data.append(record)
        
        return data
    
    # Generate sample data and train models
    sample_data = generate_sample_data(1000)
    X, y = predictor.prepare_training_data(sample_data)
    
    # Split data for training and testing
    X_train, X_test, y_train, y_test = train_test_split(
        X, {k: v for k, v in y.items()}, test_size=0.2, random_state=42
    )
    
    # Convert y_test back to proper format
    y_test_dict = {
        'latency': y_test['latency'],
        'throughput': y_test['throughput'],
        'packet_loss': y_test['packet_loss']
    }
    
    # Train models
    predictor.train_models(X_train, {
        'latency': y_train['latency'],
        'throughput': y_train['throughput'],
        'packet_loss': y_train['packet_loss']
    })
    
    # Evaluate models
    evaluation = predictor.evaluate_models(X_test, y_test_dict)
    print("Model Evaluation Results:")
    for metric, scores in evaluation.items():
        print(f"{metric.capitalize()}: R2={scores['r2']:.3f}, RMSE={scores['rmse']:.3f}")
    
    # Test prediction
    test_data = sample_data[0]
    prediction = predictor.predict_performance(test_data)
    print(f"\nSample Prediction: {prediction}")
    
    # Test future predictions
    future_predictions = predictor.predict_future_performance(test_data, horizon_minutes=10)
    print(f"\nFuture Predictions (next 10 minutes): {len(future_predictions)} predictions generated")
    
    # Save models
    predictor.save_models()
    print("\nModels saved successfully")
