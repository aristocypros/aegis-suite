export default function Toast({ message, type }) {
  return (
    <div className={`toast ${type === "error" ? "error" : ""}`}>
      <span>{message}</span>
    </div>
  );
}
