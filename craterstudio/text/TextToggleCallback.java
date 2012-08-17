/*
 * Created on 21 jun 2011
 */

package craterstudio.text;

public interface TextToggleCallback
{
   public void onMatch(String value);

   public void onOther(String value);

   public void onDone(boolean endedInMatch);
}