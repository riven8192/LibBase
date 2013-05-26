/*
 * Created on 30 mrt 2010
 */

package craterstudio.streams;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import sun.misc.BASE64Encoder;

import craterstudio.text.Text;

public class MultipartOutputStream extends OutputStream
{
   final OutputStream backing;
   final String       boundary;

   public MultipartOutputStream(OutputStream backing, String boundary)
   {
      this.backing = backing;
      this.boundary = boundary;
   }

   public void writeMimeHeader(MultipartType type) throws IOException
   {
      this.backing.write(Text.ascii("MIME-Version: 1.0\r\n"));
      this.backing.write(Text.ascii("Content-Type: " + type.msg + "; boundary=\"" + boundary + "\"\r\n"));
      this.backing.write(Text.ascii("\r\n"));
      this.backing.write(Text.ascii("This is a message with multiple parts in MIME format.\r\n"));
   }

   boolean isInPart = false;

   public class MultipartPart extends ByteArrayOutputStream
   {
      private Map<String, String> header;

      MultipartPart(int bufferSize)
      {
         super(bufferSize);

         if (isInPart)
            throw new IllegalStateException();
         isInPart = true;

         this.header = new HashMap<String, String>();
      }

      public void setHeader(String key, String value)
      {
         this.header.put(key, value);
      }

      @Override
      public void close() throws IOException
      {
         isInPart = false;
         super.close();

         OutputStream out = MultipartOutputStream.this.backing;
         out.write(Text.ascii("--" + boundary + "\r\n"));
         {
            this.setHeader("Content-Length", String.valueOf(this.size()));
            for (Entry<String, String> entry : this.header.entrySet())
               out.write(Text.ascii(entry.getKey() + ": " + entry.getValue() + "\r\n"));
         }
         out.write(Text.ascii("\r\n"));
         out.flush();

         if (check_for_boundary_in_data)
         {
            byte[] bndr = boundary.getBytes();
            byte[] copy = this.toByteArray();

            outer: for (int i = 0; i < copy.length - bndr.length; i++)
            {
               for (int k = 0; k < bndr.length; k++)
                  if (copy[i + k] != bndr[k])
                     continue outer;
               throw new IllegalStateException("found boundary in multipart part");
            }

            out.write(copy);
         }
         else
         {
            this.writeTo(out);
         }

         out.write(Text.ascii("\r\n"));
         out.flush();
      }
   }

   public MultipartPart createPart()
   {
      return this.createPart(8 * 1024);
   }

   public MultipartPart createPart(int bufferSize)
   {
      return new MultipartPart(bufferSize);
   }

   public MultipartAttachment createAttachment()
   {
      return new MultipartAttachment();
   }

   public static final boolean check_for_boundary_in_data = false;

   public class MultipartAttachment extends MultipartPart
   {
      MultipartAttachment()
      {
         super(8 * 1024);

         this.setHeader("Content-Transfer-Encoding", "base64");
      }

      public void setContentType(String type)
      {
         this.setHeader("Content-Type", type);
      }

      public void setResource(String id, String name, boolean inline)
      {
         if (id != null)
            this.setHeader("Content-ID", "<" + id + ">");
         this.setHeader("Content-Disposition", (inline ? "inline" : "attachment") + "; filename=\"" + name + "\"");
      }

      public void setBase64(byte[] base64) throws IOException
      {
         for (byte c : base64)
         {
            if (c >= 'a' && c <= 'z')
               continue;
            if (c >= 'A' && c <= 'Z')
               continue;
            if (c >= '0' && c <= '9')
               continue;
            if (c == '+' || c == '/' || c == '=' || c == '\r' || c == '\n')
               continue;
            throw new IllegalStateException("invalid base64 char: '" + c + "' (charcode: " + (int) c + ")");
         }

         this.write(base64);
      }

      public void setBase64(String base64) throws IOException
      {
         for (char c : base64.toCharArray())
         {
            if (c >= 'a' && c <= 'z')
               continue;
            if (c >= 'A' && c <= 'Z')
               continue;
            if (c >= '0' && c <= '9')
               continue;
            if (c == '+' || c == '/' || c == '=' || c == '\r' || c == '\n')
               continue;
            throw new IllegalStateException("invalid base64 char: '" + c + "' (charcode: " + (int) c + ")");
         }

         this.write(Text.ascii(base64));
      }

      public void setRawData(byte[] data) throws IOException
      {
         this.setBase64(new BASE64Encoder().encode(data));
      }
   }

   //

   @Override
   public void write(int b) throws IOException
   {
      this.backing.write(b);
   }

   @Override
   public void write(byte[] buf) throws IOException
   {
      this.backing.write(buf);
   }

   @Override
   public void write(byte[] buf, int off, int len) throws IOException
   {
      this.backing.write(buf, off, len);
   }

   @Override
   public void flush() throws IOException
   {
      this.backing.flush();
   }

   @Override
   public void close() throws IOException
   {
      this.backing.write(Text.ascii("--" + boundary + "--\r\n\r\n"));
      this.backing.flush();
      this.backing.close();

      if (isInPart)
         throw new IllegalStateException();
   }
}
