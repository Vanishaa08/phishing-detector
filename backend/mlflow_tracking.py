import mlflow
import mlflow.sklearn
import joblib
import os
import sys
sys.path.append(os.path.dirname(__file__))

MLFLOW_TRACKING_URI = "sqlite:///mlflow/mlflow.db"
EXPERIMENT_NAME = "phishguard-phishing-detection"

def setup_mlflow():
    os.makedirs('mlflow', exist_ok=True)
    mlflow.set_tracking_uri(MLFLOW_TRACKING_URI)
    mlflow.set_experiment(EXPERIMENT_NAME)
    print(f"MLflow tracking URI: {MLFLOW_TRACKING_URI}")
    print(f"Experiment: {EXPERIMENT_NAME}")

def log_training_run(model, params, metrics, feature_names, run_name="RandomForest"):
    setup_mlflow()
    with mlflow.start_run(run_name=run_name) as run:
        # Log parameters
        mlflow.log_params(params)
        mlflow.log_param("features_count", len(feature_names))
        mlflow.log_param("features", str(feature_names))
        mlflow.log_param("threshold", 0.35)

        # Log metrics
        mlflow.log_metrics(metrics)

        # Log model to registry
        mlflow.sklearn.log_model(
            model,
            artifact_path="model",
            registered_model_name="PhishGuard-RandomForest"
        )

        # Save feature names as artifact
        with open("mlflow/feature_names.txt", "w") as f:
            f.write("\n".join(feature_names))
        mlflow.log_artifact("mlflow/feature_names.txt")

        run_id = run.info.run_id
        print(f"\nMLflow Run ID: {run_id}")
        print(f"Experiment ID: {run.info.experiment_id}")
        return run_id

def log_comparison_run(model_name, model, metrics):
    setup_mlflow()
    with mlflow.start_run(run_name=f"Comparison_{model_name}"):
        mlflow.log_param("model_type", model_name)
        mlflow.log_metrics(metrics)
        print(f"Logged {model_name}: AUC={metrics.get('roc_auc', 'N/A')}")

def get_best_run():
    setup_mlflow()
    client = mlflow.tracking.MlflowClient()
    experiment = client.get_experiment_by_name(EXPERIMENT_NAME)
    if not experiment:
        return None
    runs = client.search_runs(
        experiment_ids=[experiment.experiment_id],
        order_by=["metrics.roc_auc DESC"],
        max_results=1
    )
    return runs[0] if runs else None