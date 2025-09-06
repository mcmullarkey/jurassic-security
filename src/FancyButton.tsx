interface FancyButtonProps {
  text: string;
  onClick: () => void;
}

const FancyButton = ({ text, onClick }: FancyButtonProps) => {
  return <button className="bg-blue-500 text-white p-4 rounded-lg"
  onClick = {onClick}>
       {text}
    </button>
}

export default FancyButton;