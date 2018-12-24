using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

public interface IScreen
{
	void Process(MenuStack stack);
	void OnEnter();
	void OnExit();
}
