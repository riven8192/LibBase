/*
 * Created on 21 jun 2011
 */

package craterstudio.text;

import java.util.ArrayList;
import java.util.List;

import craterstudio.data.tuples.Pair;

public class TextTest
{
   public static void main(String[] args)
   {
      System.out.println("-----------------");
      testToggleWhitespace();
      System.out.println("-----------------");
      testToggleQuotes();
      System.out.println("-----------------");
      testToggleOnChar();
      System.out.println("-----------------");
   }

   static void testToggleWhitespace()
   {
      TextToggle.toggleOnWhitespace("hello world", debugCallback());
      TextToggle.toggleOnWhitespace("hello  world", debugCallback());
      TextToggle.toggleOnWhitespace(" hello  world", debugCallback());
      TextToggle.toggleOnWhitespace("hello  world ", debugCallback());
      TextToggle.toggleOnWhitespace(" hello  world ", debugCallback());
   }

   static void testToggleQuotes()
   {
      TextToggle.toggleOnEscapebleChar("abc def", '\'', debugCallback());
      TextToggle.toggleOnEscapebleChar("abc 'def' ghi", '\'', debugCallback());
      TextToggle.toggleOnEscapebleChar("'def' ghi", '\'', debugCallback());
      TextToggle.toggleOnEscapebleChar("abc 'def'", '\'', debugCallback());
      TextToggle.toggleOnEscapebleChar("abc 'def\\\\'ghi' jkl", '\'', debugCallback());
      TextToggle.toggleOnEscapebleChar("abc \"def\\\"ghi\" jkl", '"', debugCallback());
      TextToggle.toggleOnEscapebleChar("abc \"def\\\\\"ghi\" jkl", '"', debugCallback());
      TextToggle.toggleOnEscapebleChar("a\\\"bc \"def\\\"ghi\" jkl", '"', debugCallback());
      TextToggle.toggleOnEscapebleChar("'def' ghi\\' 'boo''boo", '\'', debugCallback());
      TextToggle.toggleOnEscapebleChar("'def' ghi\\' 'boo''boo'", '\'', debugCallback());
   }

   static void testToggleOnChar()
   {
      TextToggle.toggleOnChar("hello world bye world ", ' ', false, debugCallback());
      TextToggle.toggleOnChar(" hello world bye world ", ' ', false, debugCallback());
      TextToggle.toggleOnChar("hello world bye world ", ' ', true, debugCallback());
      TextToggle.toggleOnChar(" hello world bye world ", ' ', true, debugCallback());
   }

   static TextToggleCallback debugCallback()
   {
      return new TextToggleCallback()
      {
         List<Pair<Boolean, String>> chain = new ArrayList<Pair<Boolean, String>>();

         @Override
         public void onOther(String value)
         {
            this.chain.add(new Pair<Boolean, String>(Boolean.FALSE, value));
         }

         @Override
         public void onMatch(String value)
         {
            this.chain.add(new Pair<Boolean, String>(Boolean.TRUE, value));
         }

         @Override
         public void onDone(boolean endedInMatch)
         {
            StringBuilder sb = new StringBuilder();
            for (Pair<Boolean, String> item : this.chain)
            {
               if (sb.length() > 0)
                  sb.append(", ");
               if (item.first().booleanValue())
                  sb.append("[");
               sb.append("\"" + item.second() + "\"");
               if (item.first().booleanValue())
                  sb.append("]");
            }

            System.out.println(sb);
         }
      };
   }
}
