package ghidorah;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Cursor;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import java.awt.Toolkit;
import java.awt.Window;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSlider;
import javax.swing.JTextArea;
import javax.swing.LookAndFeel;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.UnsupportedLookAndFeelException;
import javax.swing.border.EmptyBorder;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import javax.swing.plaf.metal.MetalLookAndFeel;
import javax.swing.plaf.metal.MetalTheme;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.*;
import ghidra.app.util.exporter.Exporter;
import ghidra.app.util.exporter.ExporterException;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.AddressSetView;
import ghidra.util.task.TaskMonitor;
import docking.ComponentProvider;
import docking.widgets.table.GFilterTable;
import ghidra.app.services.GoToService;
import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.util.table.GhidraFilterTable;
import ghidra.util.table.GhidraTable;

/**
 * @author quosego
 *
 */
public class GhidorahProvider extends ComponentProvider {
	private static final String PROVIDER_TITLE = "Ghidorah Plugin";
	
	private GhidorahPlugin plugin;
	
	private JComponent component;
	
	private JSlider sliderHue;
	private JSlider sliderSaturation;
	private JSlider sliderBrightness;
	
	private JLabel labelMessage;
	
	private JButton buttonDefault;
	private JButton buttonOkay;
	private JButton buttonCancel;

	private Thread threadTheme;

	public GhidorahProvider(GhidorahPlugin plugin) {
		super(plugin.getTool(), PROVIDER_TITLE, plugin.getName());
		
		this.plugin = plugin;
		component = build();
	}
	
	private JComponent build() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.add(buildControlPanel(), BorderLayout.CENTER);
		panel.setVisible(true);
		return panel;
	}

	void dispose() {
		removeFromTool();
	}

	@Override
	public JComponent getComponent() {
		return component;
	}
	
	private Component buildControlPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBounds(100, 100, 450, 300);
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

		return panel;
	}
}
