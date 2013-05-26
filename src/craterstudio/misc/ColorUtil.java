package craterstudio.misc;

import java.awt.Color;

import craterstudio.math.EasyMath;
import craterstudio.math.Vec3;

public class ColorUtil
{
   public static final Color fade(Color c, float mul)
   {
      int r = c.getRed();
      int g = c.getGreen();
      int b = c.getBlue();
      int a = c.getAlpha();

      return new Color(r, g, b, (int) (a * mul));
   }

   public static final Color normalize(Color c)
   {
      int r = c.getRed();
      int g = c.getGreen();
      int b = c.getBlue();
      int a = c.getAlpha();

      Vec3 v = new Vec3(r, g, b).normalize();

      r = (int) (v.x * 0xFF);
      g = (int) (v.y * 0xFF);
      b = (int) (v.z * 0xFF);

      return new Color(r, g, b, a);
   }

   public static final Color saturate(Color c, float n)
   {
      float r = c.getRed();
      float g = c.getGreen();
      float b = c.getBlue();

      r /= 255.0F;
      g /= 255.0F;
      b /= 255.0F;

      //

      r = (float) Math.pow(r, n);
      g = (float) Math.pow(g, n);
      b = (float) Math.pow(b, n);

      //

      r *= 255.0F;
      g *= 255.0F;
      b *= 255.0F;

      int r0 = EasyMath.clamp((int) r, 0, 255);
      int g0 = EasyMath.clamp((int) g, 0, 255);
      int b0 = EasyMath.clamp((int) b, 0, 255);

      return new Color(r0, g0, b0, c.getAlpha());
   }

   public static final Color brightness(Color c, float mul)
   {
      float r = c.getRed();
      float g = c.getGreen();
      float b = c.getBlue();

      r *= mul;
      g *= mul;
      b *= mul;

      // overflow red
      while (r > 255.0F)
      {
         g += 0.5F;
         b += 0.5F;
         r -= 1.0F;
      }
      // overflow green
      while (g > 255.0F)
      {
         r += 0.5F;
         b += 0.5F;
         g -= 1.0F;
      }
      // overflow blue
      while (b > 255)
      {
         r += 0.5F;
         g += 0.5F;
         b -= 1.0F;
      }

      // underflow red
      while (r < 0.0F)
      {
         g -= 0.5F;
         b -= 0.5F;
         r += 1.0F;
      }
      // underflow green
      while (g < 0.0F)
      {
         r -= 0.5F;
         b -= 0.5F;
         g += 1.0F;
      }
      // underflow blue
      while (b < 0.0F)
      {
         r -= 0.5F;
         g -= 0.5F;
         b += 1.0F;
      }

      int r0 = EasyMath.clamp((int) r, 0, 255);
      int g0 = EasyMath.clamp((int) g, 0, 255);
      int b0 = EasyMath.clamp((int) b, 0, 255);

      return new Color(r0, g0, b0, c.getAlpha());
   }
}
