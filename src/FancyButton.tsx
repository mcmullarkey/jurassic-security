interface FancyButtonProps {
  text: string;
  onClick: () => void;
}

const FancyButton = ({ text, onClick }: FancyButtonProps): React.JSX.Element => {
  return <button className="bg-blue-500 text-white p-4 rounded-lg"
  onClick = {onClick}>
       {text}
    </button>
}

export default FancyButton;