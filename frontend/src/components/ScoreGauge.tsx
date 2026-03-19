interface ScoreGaugeProps {
  score: number;
}

export function ScoreGauge({ score }: ScoreGaugeProps) {
  const radius = 54;
  const stroke = 6;
  const circumference = 2 * Math.PI * radius;
  const progress = (score / 100) * circumference;
  const offset = circumference - progress;

  let color: string;
  let ringColor: string;
  let glowColor: string;
  if (score < 40) {
    color = 'text-red-400';
    ringColor = 'stroke-red-500';
    glowColor = 'rgba(239,68,68,0.15)';
  } else if (score <= 70) {
    color = 'text-amber-400';
    ringColor = 'stroke-amber-500';
    glowColor = 'rgba(245,158,11,0.15)';
  } else {
    color = 'text-emerald-400';
    ringColor = 'stroke-emerald-500';
    glowColor = 'rgba(16,185,129,0.15)';
  }

  return (
    <div className="flex flex-col items-center gap-1">
      <div className="relative" style={{ filter: `drop-shadow(0 0 16px ${glowColor})` }}>
        <svg width="128" height="128" viewBox="0 0 128 128">
          <circle
            cx="64"
            cy="64"
            r={radius}
            fill="none"
            stroke="currentColor"
            className="text-gray-800"
            strokeWidth={stroke}
          />
          <circle
            cx="64"
            cy="64"
            r={radius}
            fill="none"
            className={ringColor}
            strokeWidth={stroke}
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            transform="rotate(-90 64 64)"
            style={{ transition: 'stroke-dashoffset 0.8s ease-out' }}
          />
        </svg>
        <div className="absolute inset-0 flex items-center justify-center">
          <span className={`text-3xl font-bold tabular-nums ${color}`}>
            {score}
          </span>
        </div>
      </div>
      <span className="text-xs text-gray-500 font-medium tracking-wider uppercase">Score</span>
    </div>
  );
}
