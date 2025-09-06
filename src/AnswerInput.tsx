interface AnswerInputProps {
  value: string;
  onChange: (value: string) => void;
}

function AnswerInput({ value, onChange }: AnswerInputProps): React.JSX.Element {
  return (
    <div className="flex flex-col items-center gap-2 p-4">
      <input 
        type="text" 
        placeholder="Enter your answer..." 
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
      />
    </div>
  );
}

export default AnswerInput;