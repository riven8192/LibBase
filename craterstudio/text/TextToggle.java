/*
 * Created on 21 jun 2011
 */

package craterstudio.text;

public class TextToggle
{
   public static final void toggleOnWhitespace(String input, TextToggleCallback callback)
   {
      TextToggle.toggle(input, callback, new TextToggleMatcher()
      {
         @Override
         public TextToggleState matches(boolean inMatch, char c)
         {
            return (c == ' ' || c == '\t' || c == '\r' || c == '\n') ? TextToggleState.MATCH_INCL : TextToggleState.NO_MATCH_INCL;
         }
      });
   }

   public static final void toggleOnChar(String input, final char find, final boolean include, TextToggleCallback callback)
   {
      TextToggle.toggle(input, callback, new TextToggleMatcher()
      {
         @Override
         public TextToggleState matches(boolean inMatch, char c)
         {
            if (c != find)
               return inMatch ? TextToggleState.MATCH_INCL : TextToggleState.NO_MATCH_INCL;
            if (include)
               return inMatch ? TextToggleState.NO_MATCH_INCL : TextToggleState.MATCH_INCL;
            return inMatch ? TextToggleState.NO_MATCH_EXCL : TextToggleState.MATCH_EXCL;
         }
      });
   }

   public static final void toggleOnEscapebleChar(String input, final char find, TextToggleCallback callback)
   {
      TextToggle.toggleOnEscapebleChar(input, find, '\\', callback);
   }

   public static final void toggleOnEscapebleChar(String input, final char find, final char escape, TextToggleCallback callback)
   {
      TextToggle.toggle(input, callback, new TextToggleMatcher()
      {
         boolean escaping = false;

         @Override
         public TextToggleState matches(boolean inMatch, char c)
         {
            if (c == escape && (this.escaping ^= true))
               return inMatch ? TextToggleState.MATCH_EXCL : TextToggleState.NO_MATCH_EXCL;

            boolean match = (c == find);
            if (match && this.escaping)
               this.escaping = match = false;

            if (match)
               return inMatch ? TextToggleState.NO_MATCH_EXCL : TextToggleState.MATCH_EXCL;
            return inMatch ? TextToggleState.MATCH_INCL : TextToggleState.NO_MATCH_INCL;
         }
      });
   }

   public static final void toggle(String s, TextToggleCallback callback, TextToggleMatcher matcher)
   {
      StringBuilder building = new StringBuilder();
      boolean isInMatch = false;

      for (int i = 0; i < s.length(); i++)
      {
         char c = s.charAt(i);

         TextToggleState state = matcher.matches(isInMatch, c);
         boolean matches = (state == TextToggleState.MATCH_INCL) || (state == TextToggleState.MATCH_EXCL);

         if (matches != isInMatch)
         {
            if (i != 0)
            {
               String value = building.toString();
               if (isInMatch)
                  callback.onMatch(value);
               else
                  callback.onOther(value);
            }

            building.setLength(0);

            isInMatch = matches;
         }

         if (state != TextToggleState.MATCH_EXCL && state != TextToggleState.NO_MATCH_EXCL)
            building.append(c);
      }

     // if (building.length() > 0) // KEEP IT THIS WAY!
      {
         String value = building.toString();
         if (isInMatch)
            callback.onMatch(value);
         else
            callback.onOther(value);
      }
      callback.onDone(isInMatch);
   }
}
