"""
ML Model Server for Packet Analysis
Servers trained models for anomaly detection, threat classification, and performance prediction
"""

import asyncio
import json
import logging
import pickle
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from datetime import datetime

import numpy as np
import pandas as pd
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import joblib
import uvicorn
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
import redis
import aioredis
from prometheus_client import Counter, Histogram, Gauge, start_http_server

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(actime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Prometheus metrics

# Pydantic models for API
class PacketFeatures(BaseModel):
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packet_size: int
    flags: List[str] = []
    payload_entropy: float = 0.0
    inter_arrival_time: float = 0.0
    window_size: int = 0
    ttl: int = 64
    fragment_offset: int = 0
    tcp_seq: Optional[int] = None
    tcp_ack: Optional[int] = None  

class FlowFeatures(BaseModel):
    flow_id: str
    duration: float
    total_packets: int
    total_bytes: int
    avg_packet_size: float
    packet_rate: float
    byte_rate: float
    protocol_distribution: Dict[str, int]
    port_distribution: Dict[str, int]
    unique_ips: int
    bidirectional_packets: int
    payload_entropy_avg: float
    inter_arrival_times: List[float]

class PredictionRequest(BaseModel):
    model_type: str = Field(..., description="Type of model: anomaly, threat, or performance")
    features: Dict[str, Any] = Field(..., description="Feature dictionary for prediction")
    metadata: Dict[str, Any] = Field(default_factory=dict)

class PredictionResponse(BaseModel): 
    prediction: Any
    confidence: float
    model_version: str
    timestamp: datetime
    processing_time_ms: float
    metadata: Dict[str, Any] = Field(default_factory=dict)

class ModelMetrics(BaseModel):
    model_type: str
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    last_updated: datetime
    prediction_count: int

@dataclass
class ModelContainer:
    model: Any
    scaler: StandardScaler
    feature_names: List[str]
    version: str
    accuracy: float
    created_at: datetime
    last_used: datetime
    prediction_count: int = 0

class MLModelServer: 
    def __init__(self, config_path: str = "configs/ml_config.json"):
        self.app = FastAPI(title="Packet Analysis ML Server", version="1.0.0")
        self.models: Dict[str, ModelContainer] = {}
        self.redis_client: Optional[aioredis.Redis] = None
        self.config = self._load_config(config_path)
        self.setup_routes()
        self.setup_middleware()
    
    def _load_config(self, config_path: str) -> Dict:
        """Load configuration from JSON file"""

        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            logger.warning(f"Config file {config_path} not found, using defaults")
            return {
                "redis_url": "redis://localhost:6379",
                "model_paths": {
                    "anomaly": "models/anomaly_model.pkl",
                    "threat": "models/threat_model.pkl",
                    "performance": "models/performance_model.pkl"
                },
                "feature_engineering": {
                    "window_size": 100,
                    "sliding_window": True,
                    "normalize_features": True
                },
                "thresholds": {
                    "anomaly_thresholds": 0.5,
                    "threat_threshold": 0.7,
                    "performance_threshold": 0.6
                }
            }
        
    def setup_middleware(self):
        """Setup FastAPI middleware"""
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    def setup_routes(self): 
        """Setup API routes"""

        @self.app.on_event("startup")
        async def startup_event():
            await self.initialize_redis()
            await self.load_models()
            start_http_server(8001)          # Prometheus metrics server
            logger.info("ML Model Server started successfully")

        @self.app.on_event("shutdown")
        async def shutdown_event():
            if self.redis_client:
                await self.redis_client.close()
            logger.info("ML Model Server shut down")
        
        @self.app.get("/health")
        async def health_check():
            return {"status": "healthy", "models_loaded": len(self.models)}
        
        @self.app.get("/models")
        async def list_models():
            return {
                name: {
                    "version": container.version,
                    "accuracy": container.accuracy,
                    "last_used": container.last_used.isoformat(),
                    "prediction_count": container.prediction_count
                }
                for name, container in self.models.items()
            }
        
        @self.app.post("/predict", response_model=PredictionResponse)
        async def predict(request: PredictionRequest):
            return await self.make_prediction(request)
        
        @self.app.post("/predict/batch")
        async def predict_batch(requests: List[PredictionRequest]):
            tasks = [self.make_prediction(req) for req in requests]
            return await asyncio.gather(*tasks)
        
        @self.app.get("/metrics/{model_type}")
        async def get_model_metrics(model_type: str):
            if model_type not in self.models:
                raise HTTPException(status_code=404, detail="Model not found")
            
            container = self.models[model_type]
            return ModelMetrics(
                model_type=model_type,
                accuracy=container.accuracy,
                precision=0.0,     # would be calculated from validation data
                recall=0.0,
                f1_score=0.0,
                last_updated=container.created_at,
                prediction_count=container.prediction_count
            )
        
        @self.app.post("/retrain/{model_type}")
        async def retrain_model(model_type: str, background_tasks: BackgroundTasks):
            if model_type not in self.models:
                raise HTTPException(status_code=404, detail="Model not found")
            
            background_tasks.add_task(self.retrain_model_background, model_type)
            return {"message": f"Retraining {model_type} model started"}
    
    async def initialize_redis(self):
        """Initialize Redis connection"""
        try:
            self.redis_client = await aioredis.from_url(
                self.config["redis_url"],
                encoding="utf-8",
                decode_responses=True
            )
            await self.redis_client.ping()
            logger.info("Redis connection established")
        except Exception as e:
            logger.info(f"Failed to connect to Redis: {e}")
            self.redis_client = None
    
    async def load_models(self):
        """Load all ML models from disk"""
        model_paths = self.config["model_paths"]

        for model_type, model_path in model_paths.items():
            try:
                await self.load_model(model_type, model_path)
                logger.info(f"Loaded {model_type} model from {model_path}")
            except Exception as e:
                logger.error(f"Failed to load {model_type} model: {e}")
                # Load default model if specific model fails
                await self.load_default_model(model_type)

        ACTIVE_MODELS.set(len(self.models))

    
    async def load_model(self, model_type: str, model_path: str):
        """Load a specific model from disk"""

        model_path_obj = Path(model_path)

        if not model_path_obj.exists():
            raise FileNotFoundError(f"Model file not found: {model_path}")

        # Load model and associated artifacts
        with open(model_path, 'rb') as f:
            model_data = pickle.load(f)

        model = model_data['model']
        scaler = model_data.get('scaler', StandardScaler())
        feature_names = model_data.get('feature_names', [])
        version = model_data.get('version', '1.0.0')
        accuracy = model_data.get('accuracy', 0.0)

        container = ModelContainer(
            model=model,
            scaler=scaler,
            feature_names=feature_names,
            version=version,
            accuracy=accuracy,
            created_at=datetime.now(),
            last_used=datetime.now()
        )

        self.models[model_type] = container
        MODEL_ACCURACY.labels(model_type=model_type).set(accuracy)

    async def load_default_model(self, model_type: str):
        """Load a default model when specific model fails"""
        logger.info(f"Loading default {model_type} model")
        
        if model_type == "anomaly":
            model = IsolationForest(contamination=0.1, random_state=42)
        elif model_type == "threat":
            model = RandomForestClassifier(n_estimators=100, random_state=42)
        else:  # performance
            model = RandomForestClassifier(n_estimators=50, random_state=42)

        # Create dummy training data for default model
        X_dummy = np.random.rand(1000, 20)
        y_dummy = np.random.randint(0, 2, 1000) if model_type != "anomaly" else None
        
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X_dummy)
        
        if model_type == "anomaly":
            model.fit(X_scaled)
        else:
            model.fit(X_scaled, y_dummy)

        feature_names = [f"feature_{i}" for i in range(20)]
        
        container = ModelContainer(
            model=model,
            scaler=scaler,
            feature_names=feature_names,
            version="default_1.0.0",
            accuracy=0.5,
            created_at=datetime.now(),
            last_used=datetime.now()
        )

        self.models[model_type] = container
    
    async def make_prediction(self, request: PredictionRequest) -> PredictionResponse:
        """Make prediction using specified model"""
        start_time = time.time()

        if request.model_type not in self.models:
            raise HTTPException(status_code=404, detail=f"Model {request.model_type} not found")
        
        container = self.models[request.model_type]

        try:
            # Feature engineering 
            features = await self.engineer_features(request.features, request.model_type)

            # make prediction
            with PREDICTION_DURATION.labels(model_type=request.model_type).time():
                prediction, confidence = await self.predict_with_model(
                    container, features, request.model_type
                )
            
            # Update metrics
            container.last_used = datetime.now()
            container.prediction_count += 1

            result_label = "anomaly" if prediction == 1 else "normal"
            PREDICTIONS_TOTAL.labels(model_type=request.model_type, result=result_label).inc()

            # Cache prediction if Redis is available
            if self.redis_client:
                await self.cache_prediction(request, prediction, confidence)

            processing_time = (time.time() - start_time) * 1000

            return PredictionResponse(
                prediction=prediction,
                confidence=confidence,
                model_version=container.version,
                timestamp=datetime.now(),
                processing_time_ms=processing_time,
                metadata=request.metadata
            )
        
        except Exception as e:
            logger.error(f"Prediction failed: {e}")
            raise HTTPException(status_code=500, detail=f"Prediction failed: {str(e)}")
        
    async def engineer_features(self, raw_features: Dict[str, Any], model_type: str) -> np.ndarray:
        """Engineer features for model input"""

        if model_type == "anomaly":
            return self._engineer_anomaly_features(raw_features)
        elif model_type == "threats":
            return self._engineer_threat_features(raw_features)
        else:    # performance
            return self._engineer_performance_features(raw_features)
        
    def _engineer_anomaly_features(self, features: Dict[str, Any]) -> np.ndarray:
        """Engineer features for anomaly detection"""
        feature_vector = []

        # Basic packet fetures
        feature_vector.extend([
            features.get('packet_size', 0),
            features.get('inter_arrival_time', 0),
            features.get('payload_entropy', 0),
            features.get('window_size', 0),
            features.get('ttl', 0),
            features.get('fragment_offset', 0),
        ])

        # protocol encoding
        protocol_map = {'TCP': 0, 'UDP': 1, 'ICMP': 2, 'OTHER': 3}
        feature_vector.append(protocol_map.get(features.get('protocol', 'OTHER'), 3))

        # port analysis
        src_port = features.get('src_port', 0)
        dst_port = features.get('dst_port', 0)
        feature_vector.extend([
            1 if src_port < 1024 else 0,  # well-known port
            1 if dst_port < 1024 else 0, 
            1 if src_port == dst_port else 0,   # same port
        ])

        # flags analysis
        flags = features.get('flags', [])
        flags_features = [1 if flag in flags else 0 for flag in ['SYN', 'ACK', 'FIN', 'RST', 'PSH', 'URG']]
        feature_vector.extend(flags_features)

        #time-based features
        hour = datetime.fromtimestamp(features.get('timestamp', time.time())).hour
        feature_vector.extend([
            1 if 9 <= hour <= 17 else 0,     # business hour
            1 if hour <= 6 or hour >= 22 else 0  # night hours
        ])

        return np.array(feature_vector).reshape(1, -1)
    
    def _engineer_threat_features(self, features: Dict[str, Any]) -> np.ndarray:
        """Engineer features for threat detection"""
        feature_vector = []

        # all anomaly fetures
        anomaly_features = self._engineer_anomaly_features(features).flatten()
        feature_vector.extend(anomaly_features)

        # additional threat-specific features
        # suspicious port combinations
        src_port = features.get('src_port', 0)
        dst_port = features.get('dst_port', 0) 
        suspicious_ports = [22, 23, 135, 139, 445, 1433, 3389, 5432]

        feature_vector.extend([
            1 if src_port in suspicious_ports else 0,
            1 if dst_port in suspicious_ports else 0, 
            1 if src_port > 49152 else 0,   # ephemeral port
        ])

        # payload analysis
        payload_size = features.get('packet_size', 0) - 40     # minus headers
        feature_vector.extend([
            1 if payload_size > 1400 else 0,     # large payload
            1 if payload_size == 0 else 0  # empty payload
        ])

        return np.array(feature_vector).reshape(1, -1)
    
    def _engineer_performance_features(self, features: Dict[str, Any]) -> np.ndarray:
        """Engineer features for threat detection"""
        feature_vector = []

        # flow-based features
        if 'flow_features' in features:
            flow = features['flow_features']
            feature_vector.extend([
                flow.get('duration', 0),
                flow.get('total_packets', 0),
                flow.get('total_bytes', 0),
                flow.get('avg_packet_size', 0),
                flow.get('packet_rate', 0),
                flow.get('byte_rate', 0),
                flow.get('unique_ips', 0),
                flow.get('bidirectional_packets', 0),
            ])
        else:
            feature_vector.extend([0] * 8)

        # Network conditions
        feature_vector.extend([
            features.get('inter_arrival_time', 0),
            features.get('window_size', 0),
            features.get('packet_size', 0),
        ])

        #time-based features
        hour = datetime.fromtimestamp(features.get('timestamp', time.time())).hour
        feature_vector.extend([
            hour / 24.0,     # normalized hour
            1 if 9 <= hour <= 17 else 0  # business hours
        ])

        return np.array(feature_vector).reshape(1, -1)
    
    async def predict_with_model(self, container: ModelContainer, features: np.ndarray, model_type: str) -> Tuple[Any, float]:
        """Make prediction with specific model"""

        #scale features
        if hasattr(container.scaler, 'transform'):
            features_scaled = container.scaler.transform(features)
        else:
            features_scaled = features

        #Make prediction
        if model_type == "anomaly":
            prediction = container.model.predict(features_scaled)[0]
            # for anomaly detection, confidence is the anomaly score
            if hasattr(container.model, 'decision_function'):
                confidence = abs(container.model.decision_function(features_scaled)[0])
            else:
                confidence = 0.5
        else:
            prediction = container.model.predict(features_scaled)[0]
            # for classification, get prediction probabilities
            if hasattr(container.model, 'predict_proba'):
                probabilities = container.model.predict_proba(features_scaled)[0]
                confidence = max(probabilities)
            else:
                confidence = 0.5
        return prediction, confidence

    async def cache_prediction(self, request: PredictionRequest, prediction: Any, confidence: float):
        """Cache prediction result in redis"""
        try:
            cache_key = f"prediction:{request.model_type}:{hash(str(request.features))}" 
            cache_data = {
                'prediction': prediction,
                'confidence': confidence,
                'timestamp': datetime.now().isoformat(),
                'model_type': request.model_type
            }

            await self.redis_client.setex(
                cache_key,
                300,    # 5 minutes TTL
                json.dumps(cache_data, default=str)
            )
        except Exception as e:
            logger.warning(f"Failed to cache prediction: {e}")
    
    async def retrain_model_background(self, model_type: str):
        """Background task for model retraining"""
        try:
            logger.info(f"Starting retrainig for {model_type} model")

            # this would typically involve:
            # 1. fetching new training data
            # 2. retraining the model
            # 3. evaluating performance
            # 4. updating the model if performance improves

            # placeholder for actual retraining logic
            await asyncio.sleep(10)     # simulate training time
            logger.info(f"Retraining completed for {model_type} model")
        
        except Exception as e:
            logger.error(f"Retraining failed for {model_type}: {e}")

def main():
    """Main entry point"""
    server = MLModelServer()
    uvicorn.run(
        server.app,
        host="0.0.0.0",
        port=8000,
        log_level="info",
        access_log=True,
        workers=1        # keep as 1 for shared state
    )

if __name__ == "__main__":
    main()
