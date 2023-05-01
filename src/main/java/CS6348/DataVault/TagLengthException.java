package CS6348.DataVault;

public class TagLengthException extends Exception
{
	public TagLengthException()
	{
		super("Tag name is too long.");
	}
}