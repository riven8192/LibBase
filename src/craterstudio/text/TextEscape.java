/*
 * Created on 21 jun 2010
 */

package craterstudio.text;

import java.io.IOException;
import java.net.URLDecoder;
import java.net.URLEncoder;

public class TextEscape
{
   public static String escapeForQueryString(String text)
   {
      text = Text.replace(text, "\\", "\\\\");
      text = Text.replace(text, "'", "\'");
      text = Text.replace(text, "'", "\\'");
      text = Text.replace(text, "\n", "\\n");
      text = Text.replace(text, "\r", "\\r");
      text = Text.replace(text, "\t", "\\t");
      return text;
   }

   public static String escapeForCodeString(String text)
   {
      text = Text.replace(text, "\\", "\\\\");
      text = Text.replace(text, "'", "\'");
      text = Text.replace(text, "\"", "\\\"");
      text = Text.replace(text, "\n", "\\n");
      text = Text.replace(text, "\r", "\\r");
      text = Text.replace(text, "\t", "\\t");
      return text;
   }

   public static String escapeForXmlAttribute(String text)
   {
      text = escapeForXmlText(text);
      // text = Text.replace(text, "'", "&quot;");
      text = Text.replace(text, "\"", "&ldquo;");
      text = Text.replace(text, "\n", "&#10;");
      text = Text.replace(text, "\r", "&#13;");
      return text;
   }

   public static String unescapeForXmlAttribute(String text)
   {
      text = Text.replace(text, "&#10;", "\n");
      text = Text.replace(text, "&#13;", "\r");
      text = Text.replace(text, "&ldquo;", "\"");
      //text = Text.replace(text, "&quot;", "'");
      text = unescapeForXmlText(text);
      return text;
   }

   //

   public static String escapeForXmlText(String text)
   {
      text = Text.replace(text, "&", "&amp;");
      text = Text.replace(text, "'", "&#39;");
      text = Text.replace(text, "<", "&lt;");
      text = Text.replace(text, ">", "&gt;");
      return text;
   }

   public static String unescapeForXmlText(String text)
   {
      text = Text.replace(text, "&gt;", ">");
      text = Text.replace(text, "&lt;", "<");
      text = Text.replace(text, "&#39;", "'");
      text = Text.replace(text, "&amp;", "&");
      return text;
   }

   public static String unescapeHtmlEncoding(String text)
   {
      StringBuilder sb = null;

      while (true)
      {
         int io1 = text.indexOf("&#");
         if (io1 == -1)
         {
            if (sb == null)
               return text;
            break;
         }

         int io2 = text.indexOf(';', io1 + 2);
         if (io2 == -1)
         {
            if (sb == null)
               return text;
            break;
         }

         if (sb == null)
            sb = new StringBuilder();

         char c;
         try
         {
            int ansi = Integer.parseInt(text.substring(io1 + 2, io2));
            c = (char) ansi;
         }
         catch (NumberFormatException exc)
         {
            break;
         }

         sb.append(text.substring(0, io1));
         sb.append(c);
         text = text.substring(io2 + 1);
      }

      return sb.append(text).toString();
   }

   //

   public static String escapeForHTML(String text)
   {
      text = escapeForXmlText(text);
      text = Text.normalizeLinebreaks(text);
      text = Text.replace(text, "\n\n", "<p>");
      text = Text.replace(text, "\n", "<br/>");
      return text;
   }

   public static String unescapeForHTML(String text)
   {
      text = Text.replace(text, "<p>", "\r\n\r\n");
      text = Text.replace(text, "<br/>", "\r\n");
      text = unescapeForXmlText(text);
      return text;
   }

   //

   public static String urldecode(String value)
   {
      try
      {
         return URLDecoder.decode(value, "UTF-8");
      }
      catch (IOException exc)
      {
         throw new IllegalStateException(exc);
      }
   }

   public static String urlencode(String value)
   {
      try
      {
         return URLEncoder.encode(value, "UTF-8");
      }
      catch (IOException exc)
      {
         throw new IllegalStateException(exc);
      }
   }
}
