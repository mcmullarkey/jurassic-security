interface SecurityLevelBarProps {
  level: number;
  maxLevel?: number;
}

function SecurityLevelBar({ level, maxLevel = 5 }: SecurityLevelBarProps) {
  const levelNames: Record<number, string> = {
    1: "Trainee",
    2: "Entry Level", 
    3: "Sensitive",
    4: "Confidential",
    5: "Top Secret"
  };

  const progress = Math.min((level - 1) / (maxLevel - 1) * 100, 100);
  
  return (
    <div className="w-full max-w-md mx-auto mb-6">
      <div className="flex justify-between items-center mb-2">
        <span className="text-sm font-medium text-gray-300">Security Clearance</span>
        <span className="text-sm font-medium text-white">{levelNames[level] || `Level ${level}`}</span>
      </div>
      <div className="w-full bg-gray-700 rounded-full h-3">
        <div 
          className="bg-gradient-to-r from-green-500 to-green-400 h-3 rounded-full transition-all duration-500 ease-out"
          style={{width: `${progress}%`}}
        ></div>
      </div>
      <div className="flex justify-between text-xs text-gray-400 mt-1">
        <span>{levelNames[1]}</span>
        <span>{levelNames[maxLevel] || `Level ${maxLevel}`}</span>
      </div>
    </div>
  );
}

export default SecurityLevelBar;