import { BrainCircuit } from 'lucide-react'
import { Panel, EmptyState } from './Panel'

/* The model panel exists to keep two things apart that the original conflated.
   The live dashboard's detection is a RULE ENGINE. The trained model scores
   replayed HDFS blocks, and its published F1 was measured on complete blocks —
   which the live partial-block scores are not. Every claim here is scoped. */
export function ModelPanel({ model, onRetrain, retraining, dimmed, publicDemo = false }) {
  const current = model?.current
  const live = model?.live_scoring
  return (
    <Panel icon={BrainCircuit} title="Detection" dimmed={dimmed}
           badge={current ? `model v${current.version}` : 'no model'}
           badgeColor={current ? 'purple' : 'amber'}
           actions={!publicDemo &&
             <button className="btn btn-retrain" onClick={onRetrain} disabled={retraining}>
               {retraining ? '⏳ Retraining…' : '🧠 Retrain'}
             </button>
           }>
      <div className="panel-body">
        <div className="model-block">
          <div className="model-block-title">Live dashboard — rule engine</div>
          <div className="health-detail">
            {model?.rules?.ruleset_version} · threshold {model?.rules?.threshold}
          </div>
          <div className="panel-note">{model?.rules?.note}</div>
        </div>

        <div className="model-block">
          <div className="model-block-title">Trained model — benchmark</div>
          {!current ? (
            <EmptyState>
              No model has been trained on this host. Run <code>python -m eval.benchmark</code>
              {publicDemo ? ' locally to inspect the published model evaluation.' : ', or press Retrain.'}
            </EmptyState>
          ) : (
            <>
              <div className="health-detail">
                v{current.version} · {current.estimator} · {current.dataset?.label}
              </div>
              <div className="metric-row">
                <span>F1 <strong>{current.metrics?.f1}</strong></span>
                <span>precision <strong>{current.metrics?.precision}</strong></span>
                <span>recall <strong>{current.metrics?.recall}</strong></span>
                {current.metrics?.roc_auc != null && <span>ROC-AUC <strong>{current.metrics.roc_auc}</strong></span>}
              </div>
              <div className="health-detail">
                held out {current.test_rows?.toLocaleString()} of{' '}
                {(current.train_rows + current.test_rows)?.toLocaleString()} blocks · seed{' '}
                {current.seed} · sklearn {current.sklearn}
              </div>
              {current.delta_f1 != null && (
                <div className="health-detail">
                  Δ F1 vs v{current.version - 1}: <strong>{current.delta_f1 >= 0 ? '+' : ''}{current.delta_f1.toFixed(4)}</strong>
                  {current.delta_f1 === 0 && ' — retraining on unchanged data changes nothing'}
                </div>
              )}
            </>
          )}
        </div>

        <div className="model-block">
          <div className="model-block-title">Live block scoring</div>
          {!live ? (
            <div className="panel-note">
              {model?.live_scoring_error || 'Not scoring — start a replay source to see block verdicts.'}
            </div>
          ) : (
            <>
              <div className="health-detail">
                {live.lines_seen?.toLocaleString()} lines · {live.blocks_tracked} blocks tracked
                {live.blocks_evicted > 0 && ` · ${live.blocks_evicted} evicted`}
              </div>
              <div className="health-detail">
                {live.unmatched_lines} lines matched no template ·{' '}
                {live.out_of_vocabulary_lines} matched a template the model never saw
              </div>
              {live.recent_probabilities && (
                <div className="health-detail">
                  recent scores: min {live.recent_probabilities.min} · median{' '}
                  {live.recent_probabilities.median} · max {live.recent_probabilities.max}
                  {' '}(n={live.recent_probabilities.samples})
                </div>
              )}
              <div className="panel-note">{live.note}</div>
            </>
          )}
        </div>
      </div>
    </Panel>
  )
}
