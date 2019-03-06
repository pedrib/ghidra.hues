package ghidorah;

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import resources.ResourceManager;
import resources.Icons;

//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = "Ghidorah",
	category = PluginCategoryNames.MISC,
	shortDescription = "Color Changer",
	description = "Swing Theme Color Changer by quosego <https://github.com/quosego>"
)
//@formatter:on

/**
 * @author quosego
 *
 */
public class GhidorahPlugin extends ProgramPlugin {

	GhidorahProvider provider;
	
	public GhidorahPlugin(PluginTool tool) {
		super(tool, true, true);
		
		provider = new GhidorahProvider(this);
		
		//provider.addToTool();
		
		String topicName = this.getClass().getPackage().getName();
		String anchorName = "HelpAnchor";
		provider.setHelpLocation(new HelpLocation(topicName, anchorName));
	}

	@Override
	public void init() {
		super.init();
	}

	@Override
	protected void dispose() {
		provider.dispose();
	}
	
}
