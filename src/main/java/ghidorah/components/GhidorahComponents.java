package ghidorah.components;

import javax.swing.*;
import java.awt.*;

public class GhidorahComponents {

    private void listAllComponentsIn(Container parent)
    {
        for (Component c : parent.getComponents())
        {
            System.out.println(c.toString());

            if (c instanceof Container)
                listAllComponentsIn((Container)c);
        }
    }

    public void run()
    {
        JFrame jframe = new JFrame();
        listAllComponentsIn(jframe.getContentPane());
    }
}
