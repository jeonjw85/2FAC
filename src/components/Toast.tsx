export default function Toast({ message }: { message: string }) {
  if (!message) return null;
  return (
    <div className="toast" key={message}>
      {message}
    </div>
  );
}
